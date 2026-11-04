"""
Interface web LOCALE du scanner (commande « port-scanner-web »).

Un petit serveur HTTP, uniquement accessible depuis votre propre machine, sert une page
qui pilote le même moteur que la ligne de commande.

⚠️ Pourquoi tant de précautions pour un serveur « local » ?
Un serveur qui écoute sur 127.0.0.1 reste joignable par N'IMPORTE QUELLE page web ouverte
dans votre navigateur : un site malveillant peut tenter d'y envoyer des requêtes
(attaque CSRF) ou de contourner la politique de même origine en faisant pointer son propre
nom de domaine vers 127.0.0.1 (attaque « DNS rebinding »). Un outil capable de lancer des
scans réseau ne doit pas devenir un relais pour un site tiers.

Défenses empilées (défense en profondeur) :
  1. écoute sur la boucle locale uniquement (127.0.0.1 ou ::1), jamais sur le réseau ;
  2. jeton secret aléatoire, régénéré à chaque lancement, exigé par toute l'API ;
     il est transmis dans le FRAGMENT de l'URL (#…), que le navigateur n'envoie jamais
     au serveur ni dans l'en-tête Referer, puis dans un en-tête HTTP personnalisé ;
  3. contrôle de l'en-tête Host (bloque le DNS rebinding) ;
  4. contrôle de l'en-tête Origin sur les requêtes POST (bloque le CSRF) ;
  5. corps JSON uniquement, taille bornée ; un seul scan à la fois ;
  6. en-têtes de sécurité stricts (CSP sans script en ligne, anti-iframe, no-store…) ;
  7. le garde-fou « réseaux privés » ne peut PAS être levé depuis l'interface web.
"""

from __future__ import annotations

import argparse
import hmac
import json
import secrets
import socket
import sys
import threading
import time
import webbrowser
from collections.abc import Callable
from datetime import UTC, datetime
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from importlib import resources

from port_scanner import __version__
from port_scanner.banner import DEFAULT_BANNER_TIMEOUT
from port_scanner.ports import PRESETS, PortSpecError, parse_ports
from port_scanner.report import ScanMeta, to_json
from port_scanner.scanner import DEFAULT_CONCURRENCY, DEFAULT_TIMEOUT, MAX_CONCURRENCY, MAX_TIMEOUT, run_scan
from port_scanner.targets import DEFAULT_MAX_HOSTS, TargetError, parse_targets

# ─────────────────────────────────────────────────────────────
# 1. Constantes
# ─────────────────────────────────────────────────────────────

DEFAULT_PORT = 8765
LOOPBACK_HOSTS = ("127.0.0.1", "::1")  # seules adresses d'écoute acceptées
# Nom de l'en-tête (pas un secret) ; un en-tête personnalisé impose une requête « préliminaire » CORS
TOKEN_HEADER = "X-Scan-Token"  # noqa: S105
MAX_BODY_BYTES = 4096  # une demande de scan tient en quelques centaines d'octets
# Corps lu puis ignoré avant une réponse d'erreur (voir Handler._discard_body)
DRAIN_LIMIT_BYTES = 64 * 1024
MAX_TARGET_ENTRIES = 32  # nombre de saisies de cibles par demande

# Fichiers statiques servis : LISTE BLANCHE explicite (aucun accès au disque à partir de l'URL,
# donc aucune traversée de répertoire « ../ » possible).
STATIC_FILES = {
    "/": ("index.html", "text/html; charset=utf-8"),
    "/index.html": ("index.html", "text/html; charset=utf-8"),
    "/app.js": ("app.js", "text/javascript; charset=utf-8"),
    "/style.css": ("style.css", "text/css; charset=utf-8"),
}

# En-têtes de sécurité ajoutés à TOUTES les réponses
SECURITY_HEADERS = {
    # CSP : aucun script en ligne, aucune ressource externe, aucune intégration en iframe
    "Content-Security-Policy": (
        "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; "
        "img-src 'self' data:; base-uri 'none'; form-action 'none'; frame-ancestors 'none'"
    ),
    "X-Content-Type-Options": "nosniff",  # interdit au navigateur de « deviner » le type
    "X-Frame-Options": "DENY",  # anti-clickjacking pour les anciens navigateurs
    "Referrer-Policy": "no-referrer",
    "Cache-Control": "no-store",  # les résultats de scan ne doivent pas rester en cache
    "Cross-Origin-Opener-Policy": "same-origin",
    "Cross-Origin-Resource-Policy": "same-origin",
}


class RequestError(Exception):
    """Erreur renvoyée au client : code HTTP + message lisible."""

    def __init__(self, status: HTTPStatus, message: str) -> None:
        super().__init__(message)
        self.status = status
        self.message = message


# ─────────────────────────────────────────────────────────────
# 2. Logique métier (indépendante de HTTP, donc testable seule)
# ─────────────────────────────────────────────────────────────

# Signature de la fonction de scan : identique à scanner.run_scan (remplaçable dans les tests)
ScanFunction = Callable[..., list]


class ScanService:
    """Valide une demande de scan, l'exécute (une seule à la fois) et produit le JSON."""

    def __init__(self, scan_function: ScanFunction = run_scan) -> None:
        self._scan = scan_function
        # Verrou NON bloquant : une seconde demande pendant un scan reçoit « 409 Conflit »
        # au lieu de s'empiler (évite qu'une page boucle et sature le réseau).
        self._lock = threading.Lock()

    @staticmethod
    def _number(payload: dict, key: str, default: float, low: float, high: float, integer: bool = False) -> float:
        """Lit un nombre optionnel et vérifie son type et ses bornes."""
        value = payload.get(key, default)
        # bool est une sous-classe d'int en Python : on l'exclut explicitement
        if isinstance(value, bool) or not isinstance(value, int | float):
            raise RequestError(HTTPStatus.BAD_REQUEST, f"« {key} » doit être un nombre.")
        if integer and not isinstance(value, int):
            raise RequestError(HTTPStatus.BAD_REQUEST, f"« {key} » doit être un entier.")
        if not low <= value <= high:  # rejette aussi NaN
            raise RequestError(HTTPStatus.BAD_REQUEST, f"« {key} » doit être compris entre {low} et {high}.")
        return value

    def run(self, payload: object) -> str:
        """Exécute une demande de scan et renvoie le document JSON (même format que la CLI)."""
        if not isinstance(payload, dict):
            raise RequestError(HTTPStatus.BAD_REQUEST, "Objet JSON attendu.")

        # ── Cibles : liste de chaînes, ou une chaîne « a, b c » découpée ──
        raw_targets = payload.get("targets")
        if isinstance(raw_targets, str):
            raw_targets = raw_targets.replace(",", " ").split()
        if not isinstance(raw_targets, list) or not raw_targets or not all(isinstance(t, str) for t in raw_targets):
            raise RequestError(HTTPStatus.BAD_REQUEST, "Indiquez au moins une cible.")
        if len(raw_targets) > MAX_TARGET_ENTRIES:
            raise RequestError(HTTPStatus.BAD_REQUEST, f"{MAX_TARGET_ENTRIES} cibles au maximum par demande.")

        ports_spec = payload.get("ports", "top100")
        if not isinstance(ports_spec, str):
            raise RequestError(HTTPStatus.BAD_REQUEST, "« ports » doit être une chaîne.")
        banners = payload.get("banners", False)
        include_all = payload.get("all", False)
        if not isinstance(banners, bool) or not isinstance(include_all, bool):
            raise RequestError(HTTPStatus.BAD_REQUEST, "« banners » et « all » doivent valoir true ou false.")
        timeout = self._number(payload, "timeout", DEFAULT_TIMEOUT, 0.05, MAX_TIMEOUT)
        concurrency = int(self._number(payload, "concurrency", DEFAULT_CONCURRENCY, 1, MAX_CONCURRENCY, True))

        # ── Validation métier : même code que la CLI, garde-fou NON débrayable ──
        try:
            ports = parse_ports(ports_spec)
            targets = parse_targets(raw_targets, allow_public=False, max_hosts=DEFAULT_MAX_HOSTS)
        except (PortSpecError, TargetError) as exc:
            raise RequestError(HTTPStatus.BAD_REQUEST, str(exc)) from None

        if not self._lock.acquire(blocking=False):
            raise RequestError(HTTPStatus.CONFLICT, "Un scan est déjà en cours.")
        try:
            started = datetime.now(UTC)
            clock = time.perf_counter()
            try:
                results = self._scan(
                    targets,
                    ports,
                    timeout=timeout,
                    concurrency=concurrency,
                    grab_banners=banners,
                    banner_timeout=DEFAULT_BANNER_TIMEOUT,
                )
            except ValueError as exc:  # bornes du moteur (scan trop volumineux…)
                raise RequestError(HTTPStatus.BAD_REQUEST, str(exc)) from None
            meta = ScanMeta(
                started_at=started.isoformat(timespec="seconds"),
                duration_s=round(time.perf_counter() - clock, 3),
                targets=len(targets),
                ports=len(ports),
                settings={
                    "ports": ports_spec,
                    "timeout_s": timeout,
                    "concurrency": concurrency,
                    "banners": banners,
                    "allow_public": False,
                    "interface": "web",
                },
            )
            return to_json(results, meta, include_all)
        finally:
            self._lock.release()


# ─────────────────────────────────────────────────────────────
# 3. Serveur HTTP
# ─────────────────────────────────────────────────────────────


def _load_static(name: str) -> bytes:
    """Lit un fichier de l'interface, embarqué dans le paquet (dossier port_scanner/web)."""
    return resources.files("port_scanner").joinpath("web", name).read_bytes()


class LocalServer(ThreadingHTTPServer):
    """Serveur HTTP qui porte le jeton, la liste des hôtes autorisés et le service de scan."""

    daemon_threads = True  # les fils de requête ne bloquent pas l'arrêt du programme

    def __init__(self, host: str, port: int, service: ScanService, token: str | None = None) -> None:
        if host not in LOOPBACK_HOSTS:
            # Refus ferme : exposer ce serveur sur le réseau le rendrait pilotable à distance
            raise ValueError(f"Adresse d'écoute refusée : {host} (seules {', '.join(LOOPBACK_HOSTS)} sont permises).")
        if ":" in host:
            self.address_family = socket.AF_INET6
        super().__init__((host, port), Handler)
        self.service = service
        self.quiet = False  # True = pas de journal des requêtes
        self.token = token or secrets.token_urlsafe(32)  # 256 bits d'aléa cryptographique
        bound_port = self.server_address[1]
        # Valeurs acceptées pour l'en-tête Host (le port réel est connu après la liaison)
        self.allowed_hosts = {f"127.0.0.1:{bound_port}", f"localhost:{bound_port}", f"[::1]:{bound_port}"}
        self.allowed_origins = {f"http://{h}" for h in self.allowed_hosts}

    @property
    def url(self) -> str:
        """Adresse à ouvrir dans le navigateur, jeton dans le fragment (#)."""
        host = "[::1]" if ":" in self.server_address[0] else "127.0.0.1"
        return f"http://{host}:{self.server_address[1]}/#token={self.token}"


class Handler(BaseHTTPRequestHandler):
    """Traite une requête HTTP. Toute erreur produit une réponse JSON courte, sans détail interne."""

    server: LocalServer
    server_version = "port-scanner"  # masque la version de Python dans l'en-tête Server
    sys_version = ""
    protocol_version = "HTTP/1.1"
    # Délai par opération sur la connexion : un client qui envoie sa requête au compte-gouttes
    # (attaque « slowloris ») ne peut pas immobiliser un fil d'exécution indéfiniment.
    timeout = 10

    # ── Réponses ────────────────────────────────────────────
    def _send(self, status: HTTPStatus, body: bytes, content_type: str) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        for name, value in SECURITY_HEADERS.items():
            self.send_header(name, value)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def _send_json(self, status: HTTPStatus, text: str) -> None:
        self._send(status, text.encode("utf-8"), "application/json; charset=utf-8")

    def _send_error(self, status: HTTPStatus, message: str) -> None:
        self._send_json(status, json.dumps({"error": message}, ensure_ascii=False))

    # ── Contrôles communs ───────────────────────────────────
    def _check_host(self) -> None:
        """Bloque le DNS rebinding : le Host doit désigner la boucle locale ET notre port."""
        if self.headers.get("Host", "") not in self.server.allowed_hosts:
            raise RequestError(HTTPStatus.MISDIRECTED_REQUEST, "Hôte non autorisé.")

    def _check_token(self) -> None:
        """Exige le jeton ; comparaison à temps constant (pas de fuite par la durée de réponse)."""
        supplied = self.headers.get(TOKEN_HEADER, "")
        if not hmac.compare_digest(supplied.encode(), self.server.token.encode()):
            raise RequestError(HTTPStatus.UNAUTHORIZED, "Jeton absent ou invalide.")

    def _check_origin(self) -> None:
        """Bloque le CSRF : une requête d'écriture venant d'une autre origine est refusée."""
        origin = self.headers.get("Origin")
        if origin is not None and origin not in self.server.allowed_origins:
            raise RequestError(HTTPStatus.FORBIDDEN, "Origine non autorisée.")

    def _read_json(self) -> object:
        """Lit un corps JSON de taille bornée."""
        content_type = self.headers.get("Content-Type", "").split(";")[0].strip().lower()
        if content_type != "application/json":
            raise RequestError(HTTPStatus.UNSUPPORTED_MEDIA_TYPE, "Corps JSON attendu.")
        try:
            length = int(self.headers.get("Content-Length", ""))
        except ValueError:
            raise RequestError(HTTPStatus.LENGTH_REQUIRED, "En-tête Content-Length requis.") from None
        if not 0 <= length <= MAX_BODY_BYTES:
            raise RequestError(HTTPStatus.REQUEST_ENTITY_TOO_LARGE, "Demande trop volumineuse.")
        body = self.rfile.read(length)
        self._body_consumed = True
        try:
            return json.loads(body.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            raise RequestError(HTTPStatus.BAD_REQUEST, "JSON invalide.") from None

    def _discard_body(self) -> bool:
        """
        Lit et ignore le corps non lu d'une requête refusée ; renvoie True si la connexion
        est restée « propre » (plus aucun octet en attente).

        Fermer une connexion alors que des octets attendent d'être lus provoque, sous Windows
        notamment, une réinitialisation brutale (RST) qui peut faire perdre la réponse d'erreur
        au client. Au-delà de DRAIN_LIMIT_BYTES, on ne lit rien et la connexion sera fermée.
        """
        if self._body_consumed:
            return True
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            return False
        if length == 0:
            return True
        if not 0 < length <= DRAIN_LIMIT_BYTES:
            return False
        try:
            return len(self.rfile.read(length)) == length
        except OSError:
            return False

    # ── Routes ──────────────────────────────────────────────
    def _dispatch(self, method: str) -> None:
        self._body_consumed = False
        try:
            self._check_host()
            path = self.path.split("?", 1)[0]
            if method in ("GET", "HEAD") and path in STATIC_FILES:
                name, content_type = STATIC_FILES[path]
                self._send(HTTPStatus.OK, _load_static(name), content_type)
            elif method == "GET" and path == "/api/meta":
                self._check_token()
                meta = {
                    "version": __version__,
                    "presets": sorted(PRESETS),
                    "defaults": {"ports": "top100", "timeout": DEFAULT_TIMEOUT, "concurrency": DEFAULT_CONCURRENCY},
                    "limits": {"timeout": MAX_TIMEOUT, "concurrency": MAX_CONCURRENCY, "hosts": DEFAULT_MAX_HOSTS},
                }
                self._send_json(HTTPStatus.OK, json.dumps(meta))
            elif method == "POST" and path == "/api/scan":
                self._check_origin()
                self._check_token()
                self._send_json(HTTPStatus.OK, self.server.service.run(self._read_json()))
            elif path in STATIC_FILES or path.startswith("/api/"):
                raise RequestError(HTTPStatus.METHOD_NOT_ALLOWED, "Méthode non autorisée.")
            else:
                raise RequestError(HTTPStatus.NOT_FOUND, "Introuvable.")
        except RequestError as exc:
            # Corps non lu : on le vide. S'il ne peut pas l'être, on ferme la connexion pour qu'il
            # ne soit jamais interprété comme une requête suivante (désynchronisation HTTP).
            # Sinon on laisse la connexion ouverte, comme le prévoit HTTP/1.1 : c'est le client
            # qui la fermera, ce qui évite toute course entre la fermeture et la lecture de la réponse.
            if not self._discard_body():
                self.close_connection = True
            self._send_error(exc.status, exc.message)
        except Exception:
            # Jamais de trace technique renvoyée au client : seulement un message générique
            self.log_error("Erreur interne pendant %s %s", method, self.path.split("?", 1)[0])
            self.close_connection = True
            self._send_error(HTTPStatus.INTERNAL_SERVER_ERROR, "Erreur interne.")

    def do_GET(self) -> None:  # nom imposé par http.server
        self._dispatch("GET")

    def do_HEAD(self) -> None:
        self._dispatch("HEAD")

    def do_POST(self) -> None:
        self._dispatch("POST")

    def do_PUT(self) -> None:
        self._dispatch("PUT")

    def do_DELETE(self) -> None:
        self._dispatch("DELETE")

    def do_OPTIONS(self) -> None:
        # Aucune réponse CORS favorable : les requêtes préliminaires d'autres sites échouent
        self._dispatch("OPTIONS")

    def log_message(self, format: str, *args: object) -> None:  # signature imposée par http.server
        """Journal minimal sur la sortie d'erreur ; le jeton n'apparaît jamais (il n'est pas dans l'URL)."""
        if not self.server.quiet:
            sys.stderr.write(f"[web] {self.address_string()} {format % args}\n")


# ─────────────────────────────────────────────────────────────
# 4. Point d'entrée « port-scanner-web »
# ─────────────────────────────────────────────────────────────


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="port-scanner-web",
        description="Interface web locale du scanner (accessible uniquement depuis cette machine).",
    )
    parser.add_argument("--host", choices=LOOPBACK_HOSTS, default="127.0.0.1", help="adresse d'écoute (boucle locale)")
    parser.add_argument(
        "--port",
        type=int,
        default=DEFAULT_PORT,
        help=f"port d'écoute, 0 = choisi par le système (défaut : {DEFAULT_PORT})",
    )
    parser.add_argument("--no-browser", action="store_true", help="n'ouvre pas le navigateur automatiquement")
    parser.add_argument("-q", "--quiet", action="store_true", help="n'affiche pas le journal des requêtes")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if not 0 <= args.port <= 65535:
        print("Erreur : port d'écoute hors limites (0 à 65535).", file=sys.stderr)
        return 2
    try:
        server = LocalServer(args.host, args.port, ScanService())
    except OSError as exc:
        print(f"Erreur : impossible d'écouter sur {args.host}:{args.port} : {exc.strerror or exc}", file=sys.stderr)
        return 3
    server.quiet = args.quiet
    with server:
        print(f"Interface disponible sur : {server.url}")
        print("Ce lien contient un jeton secret : ne le partagez pas. Ctrl+C pour arrêter.")
        if not args.no_browser:
            webbrowser.open(server.url)
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            print("\nInterface arrêtée.")
    return 0
