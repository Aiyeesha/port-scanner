"""
Tests de l'interface web locale.

Un vrai serveur est démarré sur 127.0.0.1 (port choisi par le système) dans un fil
d'exécution, puis interrogé avec http.client. Les scans utilisent soit une fausse
fonction de scan (tests de l'API), soit le vrai moteur contre un port ouvert local.
"""

import http.client
import json
import socket
import threading
import time

import pytest

from port_scanner import __version__
from port_scanner.scanner import PortState, ScanResult, run_scan
from port_scanner.webui import MAX_BODY_BYTES, TOKEN_HEADER, LocalServer, RequestError, ScanService

TOKEN = "jeton-de-test"  # noqa: S105 — valeur fictive propre aux tests


# ── Outils ──────────────────────────────────────────────────
def fake_scan(targets, ports, **options):
    """Fausse fonction de scan : chaque port pair est « ouvert »."""
    return [
        ScanResult(t, p, PortState.OPEN if p % 2 == 0 else PortState.CLOSED, latency_ms=1.0)
        for t in targets
        for p in ports
    ]


@pytest.fixture
def server():
    """Démarre un serveur local et l'arrête proprement après le test."""
    srv = LocalServer("127.0.0.1", 0, ScanService(fake_scan), token=TOKEN)
    srv.quiet = True
    thread = threading.Thread(target=srv.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True)
    thread.start()
    yield srv
    srv.shutdown()
    srv.server_close()
    thread.join(timeout=5)


def request(srv, method, path, body=None, headers=None, host=None):
    """Envoie une requête et renvoie (statut, en-têtes, corps décodé)."""
    port = srv.server_address[1]
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
    try:
        all_headers = {"Host": host or f"127.0.0.1:{port}"}
        all_headers.update(headers or {})
        data = body if isinstance(body, bytes) or body is None else json.dumps(body).encode()
        conn.request(method, path, body=data, headers=all_headers)
        response = conn.getresponse()
        return response.status, dict(response.getheaders()), response.read().decode("utf-8")
    finally:
        conn.close()


def api_scan(srv, payload, **extra_headers):
    headers = {TOKEN_HEADER: TOKEN, "Content-Type": "application/json"}
    headers.update(extra_headers)
    return request(srv, "POST", "/api/scan", payload, headers)


# ── Fichiers statiques et en-têtes de sécurité ──────────────
@pytest.mark.parametrize(
    ("path", "type_"), [("/", "text/html"), ("/app.js", "text/javascript"), ("/style.css", "text/css")]
)
def test_fichiers_statiques_servis(server, path, type_):
    status, headers, body = request(server, "GET", path)
    assert status == 200 and headers["Content-Type"].startswith(type_) and body


def test_entetes_de_securite(server):
    _, headers, _ = request(server, "GET", "/")
    csp = headers["Content-Security-Policy"]
    assert "default-src 'none'" in csp and "script-src 'self'" in csp and "frame-ancestors 'none'" in csp
    assert "unsafe-inline" not in csp
    assert headers["X-Content-Type-Options"] == "nosniff"
    assert headers["X-Frame-Options"] == "DENY"
    assert headers["Cache-Control"] == "no-store"
    assert headers["Referrer-Policy"] == "no-referrer"


def test_entete_server_ne_revele_pas_python(server):
    _, headers, _ = request(server, "GET", "/")
    assert "Python" not in headers["Server"]


def test_page_sans_script_en_ligne(server):
    _, _, body = request(server, "GET", "/")
    assert "<script>" not in body and "onclick" not in body.lower()


def test_code_client_n_utilise_jamais_innerhtml(server):
    _, _, body = request(server, "GET", "/app.js")
    assert "innerHTML" not in body.replace("jamais innerHTML", "")


@pytest.mark.parametrize("path", ["/../pyproject.toml", "/web/app.js", "/%2e%2e/LICENSE", "/inconnu"])
def test_chemins_hors_liste_blanche(server, path):
    assert request(server, "GET", path)[0] == 404


# ── Contrôle de l'en-tête Host (DNS rebinding) ──────────────
@pytest.mark.parametrize("host", ["evil.example", "evil.example:8765", "127.0.0.1", "192.168.1.10:80"])
def test_host_etranger_refuse(server, host):
    status, _, body = request(server, "GET", "/", host=host)
    assert status == 421 and "Hôte" in json.loads(body)["error"]


def test_host_localhost_accepte(server):
    assert request(server, "GET", "/", host=f"localhost:{server.server_address[1]}")[0] == 200


# ── Jeton ───────────────────────────────────────────────────
def test_api_sans_jeton_refusee(server):
    assert request(server, "GET", "/api/meta")[0] == 401


def test_api_mauvais_jeton_refusee(server):
    assert request(server, "GET", "/api/meta", headers={TOKEN_HEADER: "faux"})[0] == 401


def test_jeton_dans_l_url_ne_suffit_pas(server):
    assert request(server, "GET", f"/api/meta?token={TOKEN}")[0] == 401


def test_meta_avec_jeton(server):
    status, _, body = request(server, "GET", "/api/meta", headers={TOKEN_HEADER: TOKEN})
    data = json.loads(body)
    assert status == 200 and data["version"] == __version__ and "top100" in data["presets"]


def test_jeton_genere_aleatoire_et_long():
    a = LocalServer("127.0.0.1", 0, ScanService(fake_scan))
    b = LocalServer("127.0.0.1", 0, ScanService(fake_scan))
    try:
        assert a.token != b.token and len(a.token) >= 40
        assert a.url.endswith(f"#token={a.token}")  # jeton dans le fragment, jamais dans le chemin
    finally:
        a.server_close()
        b.server_close()


# ── Origine, méthode, corps ─────────────────────────────────
def test_origine_etrangere_refusee(server):
    status, _, _ = api_scan(server, {"targets": "127.0.0.1"}, Origin="https://evil.example")
    assert status == 403


def test_origine_locale_acceptee(server):
    status, _, _ = api_scan(
        server, {"targets": "127.0.0.1", "ports": "22"}, Origin=f"http://127.0.0.1:{server.server_address[1]}"
    )
    assert status == 200


def test_options_ne_donne_aucune_autorisation_cors(server):
    status, headers, _ = request(server, "OPTIONS", "/api/scan", headers={"Origin": "https://evil.example"})
    assert status == 405 and "Access-Control-Allow-Origin" not in headers


@pytest.mark.parametrize(("method", "path"), [("GET", "/api/scan"), ("DELETE", "/api/scan"), ("POST", "/")])
def test_methode_non_autorisee(server, method, path):
    assert request(server, method, path, headers={TOKEN_HEADER: TOKEN})[0] == 405


def test_type_de_contenu_obligatoire(server):
    status, _, _ = request(
        server,
        "POST",
        "/api/scan",
        b"targets=127.0.0.1",
        {TOKEN_HEADER: TOKEN, "Content-Type": "application/x-www-form-urlencoded"},
    )
    assert status == 415


def test_corps_trop_volumineux(server):
    status, _, _ = api_scan(server, {"targets": "127.0.0.1", "x": "a" * (MAX_BODY_BYTES + 1)})
    assert status == 413


def test_json_invalide(server):
    status, _, _ = request(
        server, "POST", "/api/scan", b"{pas du json", {TOKEN_HEADER: TOKEN, "Content-Type": "application/json"}
    )
    assert status == 400


# ── Validation métier ───────────────────────────────────────
def test_scan_renvoie_le_document_json_de_la_cli(server):
    status, _, body = api_scan(server, {"targets": "127.0.0.1", "ports": "21-24"})
    doc = json.loads(body)
    assert status == 200
    assert doc["tool"] == "port-scanner" and doc["settings"]["interface"] == "web"
    assert [r["port"] for r in doc["results"]] == [22, 24]  # ports ouverts seulement par défaut
    assert doc["summary"] == {"open": 2, "closed": 2, "filtered": 0}


def test_option_all(server):
    _, _, body = api_scan(server, {"targets": ["127.0.0.1"], "ports": "21-24", "all": True})
    assert len(json.loads(body)["results"]) == 4


@pytest.mark.parametrize(
    "payload",
    [
        [],
        {"targets": ""},
        {"targets": []},
        {"targets": [1, 2]},
        {"targets": "127.0.0.1", "ports": 22},
        {"targets": "127.0.0.1", "ports": "0"},
        {"targets": "127.0.0.1", "timeout": "1"},
        {"targets": "127.0.0.1", "timeout": 0},
        {"targets": "127.0.0.1", "timeout": 31},
        {"targets": "127.0.0.1", "concurrency": 1.5},
        {"targets": "127.0.0.1", "concurrency": True},
        {"targets": "127.0.0.1", "concurrency": 501},
        {"targets": "127.0.0.1", "banners": "oui"},
        {"targets": " ".join(["127.0.0.1"] * 33)},
        {"targets": "10.0.0.0/8"},
    ],
)
def test_demandes_invalides(server, payload):
    status, _, body = api_scan(server, payload)
    assert status == 400 and json.loads(body)["error"]


@pytest.mark.parametrize("cible", ["8.8.8.8", "169.254.169.254", "::ffff:8.8.8.8"])
def test_garde_fou_non_debrayable(server, cible):
    status, _, body = api_scan(server, {"targets": cible, "allow_public": True})
    assert status == 400 and "autorisation écrite" in json.loads(body)["error"]


# ── Un seul scan à la fois ──────────────────────────────────
def test_un_seul_scan_a_la_fois():
    started = threading.Event()
    release = threading.Event()

    def slow_scan(targets, ports, **options):
        started.set()
        release.wait(5)
        return []

    service = ScanService(slow_scan)
    first = threading.Thread(target=service.run, args=({"targets": "127.0.0.1", "ports": "22"},))
    first.start()
    assert started.wait(5)
    with pytest.raises(RequestError) as exc:
        service.run({"targets": "127.0.0.1", "ports": "22"})
    assert exc.value.status == 409
    release.set()
    first.join(5)
    service.run({"targets": "127.0.0.1", "ports": "22"})  # le verrou est bien libéré


# ── Adresse d'écoute ────────────────────────────────────────
@pytest.mark.parametrize("host", ["0.0.0.0", "192.168.1.10", "", "::"])
def test_ecoute_hors_boucle_locale_refusee(host):
    with pytest.raises(ValueError, match="refusée"):
        LocalServer(host, 0, ScanService(fake_scan))


# ── De bout en bout avec le vrai moteur ─────────────────────
def test_scan_reel_d_un_port_ouvert_local():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.bind(("127.0.0.1", 0))
        listener.listen()
        port = listener.getsockname()[1]

        srv = LocalServer("127.0.0.1", 0, ScanService(run_scan), token=TOKEN)
        srv.quiet = True
        thread = threading.Thread(target=srv.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True)
        thread.start()
        try:
            started = time.perf_counter()
            status, _, body = api_scan(srv, {"targets": "127.0.0.1", "ports": str(port), "timeout": 2})
        finally:
            srv.shutdown()
            srv.server_close()
            thread.join(5)
    [result] = json.loads(body)["results"]
    assert status == 200 and result["state"] == "open" and result["port"] == port
    assert time.perf_counter() - started < 10


# ── Robustesse de la connexion ──────────────────────────────
def test_reponse_d_erreur_recue_meme_avec_un_corps_non_lu(server):
    # Corps raisonnable refusé avant lecture (mauvaise origine) : la réponse doit arriver intacte
    for _ in range(20):
        status, _, body = api_scan(server, {"targets": "127.0.0.1", "pad": "x" * 3000}, Origin="https://evil.example")
        assert status == 403 and json.loads(body)["error"]


def test_client_trop_lent_deconnecte(server, monkeypatch):
    import port_scanner.webui as webui

    monkeypatch.setattr(webui.Handler, "timeout", 0.3)
    with socket.create_connection(server.server_address, timeout=5) as client:
        client.sendall(b"GET / HTTP/1.1\r\nHost: ")  # requête jamais terminée
        started = time.perf_counter()
        assert client.recv(1024) == b""  # le serveur a fermé la connexion
        assert time.perf_counter() - started < 3


def test_connexion_reutilisable_apres_une_erreur(server):
    # Après une erreur dont le corps a été vidé, la même connexion sert la requête suivante
    port = server.server_address[1]
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
    try:
        host = {"Host": f"127.0.0.1:{port}"}
        conn.request(
            "POST", "/api/scan", body=b"x=1", headers={**host, TOKEN_HEADER: TOKEN, "Content-Type": "text/plain"}
        )
        first = conn.getresponse()
        first.read()
        conn.request("GET", "/", headers=host)
        second = conn.getresponse()
        second.read()
        assert (first.status, second.status) == (415, 200)
    finally:
        conn.close()
