"""
Interface en ligne de commande.

Exemples :
    port-scanner 127.0.0.1                         100 ports courants de la machine locale
    port-scanner 192.168.1.0/24 -p 22,80,443       trois ports sur un réseau privé
    port-scanner nas.local -p 1-1024 --banners     ports système + lecture des bannières
    port-scanner 10.0.0.5 -f json -o scan.json     résultat JSON dans un fichier
    port-scanner 10.0.0.5 --fail-on high           code 1 si un port à risque élevé est ouvert (CI)

Codes de sortie :
    0    scan terminé (et aucun port n'atteint le seuil --fail-on)
    1    au moins un port ouvert atteint le seuil de risque --fail-on
    2    erreur de saisie (cible, port, option) ou cible refusée par le garde-fou
    3    erreur d'exécution (fichier de sortie impossible à écrire…)
    130  interruption par l'utilisateur (Ctrl+C)
"""

from __future__ import annotations

import argparse
import os
import sys
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import TextIO

from port_scanner import __version__
from port_scanner.banner import DEFAULT_BANNER_TIMEOUT
from port_scanner.ports import PortSpecError, parse_ports
from port_scanner.report import ScanMeta, max_open_risk, to_csv, to_json, to_text
from port_scanner.scanner import (
    DEFAULT_CONCURRENCY,
    DEFAULT_TIMEOUT,
    Connector,
    ScanResult,
    run_scan,
)
from port_scanner.services import Risk
from port_scanner.targets import DEFAULT_MAX_HOSTS, Category, TargetError, classify, parse_targets

# ─────────────────────────────────────────────────────────────
# 1. Codes de sortie
# ─────────────────────────────────────────────────────────────
EXIT_OK = 0
EXIT_RISK = 1
EXIT_USAGE = 2
EXIT_ERROR = 3
EXIT_INTERRUPTED = 130  # convention Unix : 128 + SIGINT (2)

MAX_HOSTS_LIMIT = 65_536  # plafond absolu de --max-hosts (un /16)

# Seuils acceptés par --fail-on (noms anglais stables, comme dans le JSON)
_RISK_CHOICES = {risk.name.lower(): risk for risk in Risk}


# ─────────────────────────────────────────────────────────────
# 2. Options
# ─────────────────────────────────────────────────────────────


def _positive_float(text: str) -> float:
    """Convertisseur argparse : nombre décimal strictement positif."""
    try:
        value = float(text)
    except ValueError:
        raise argparse.ArgumentTypeError(f"nombre attendu : « {text} »") from None
    if not value > 0:  # rejette aussi NaN
        raise argparse.ArgumentTypeError(f"doit être supérieur à 0 : « {text} »")
    return value


def _bounded_int(low: int, high: int):
    """Fabrique un convertisseur argparse pour un entier compris entre low et high."""

    def convert(text: str) -> int:
        try:
            value = int(text)
        except ValueError:
            raise argparse.ArgumentTypeError(f"entier attendu : « {text} »") from None
        if not low <= value <= high:
            raise argparse.ArgumentTypeError(f"doit être compris entre {low} et {high} : « {text} »")
        return value

    return convert


def build_parser() -> argparse.ArgumentParser:
    """Construit l'analyseur d'arguments (séparé de main() pour être testable)."""
    parser = argparse.ArgumentParser(
        prog="port-scanner",
        description=(
            "Scanner de ports TCP asynchrone. "
            "À n'utiliser que sur des systèmes dont vous êtes propriétaire "
            "ou pour lesquels vous disposez d'une autorisation écrite."
        ),
        epilog="Codes de sortie : 0 succès, 1 seuil --fail-on atteint, 2 erreur de saisie, "
        "3 erreur d'exécution, 130 interruption.",
    )
    parser.add_argument(
        "targets", nargs="+", metavar="CIBLE", help="adresse IP, réseau CIDR (192.168.1.0/24) ou nom d'hôte"
    )

    scan = parser.add_argument_group("scan")
    scan.add_argument(
        "-p",
        "--ports",
        default="top100",
        help="ports : 22 | 20-25 | 22,80,443 | top100 | well-known | all (défaut : top100)",
    )
    scan.add_argument(
        "-t",
        "--timeout",
        type=_positive_float,
        default=DEFAULT_TIMEOUT,
        help=f"délai par tentative en secondes (défaut : {DEFAULT_TIMEOUT})",
    )
    scan.add_argument(
        "-c",
        "--concurrency",
        type=_bounded_int(1, 500),
        default=DEFAULT_CONCURRENCY,
        help=f"tentatives simultanées, 1 à 500 (défaut : {DEFAULT_CONCURRENCY})",
    )
    scan.add_argument(
        "--max-hosts",
        type=_bounded_int(1, MAX_HOSTS_LIMIT),
        default=DEFAULT_MAX_HOSTS,
        help=f"nombre maximal d'adresses (défaut : {DEFAULT_MAX_HOSTS})",
    )
    scan.add_argument(
        "--banners", action="store_true", help="lit la bannière des ports ouverts (plus lent, plus visible)"
    )
    scan.add_argument(
        "--banner-timeout",
        type=_positive_float,
        default=DEFAULT_BANNER_TIMEOUT,
        help=f"délai de lecture d'une bannière en secondes (défaut : {DEFAULT_BANNER_TIMEOUT})",
    )
    scan.add_argument(
        "--allow-public",
        action="store_true",
        help="lève le garde-fou : autorise les cibles hors réseaux privés (uniquement avec une autorisation écrite)",
    )

    out = parser.add_argument_group("sortie")
    out.add_argument(
        "-f", "--format", choices=("text", "json", "csv"), default="text", help="format du résultat (défaut : text)"
    )
    out.add_argument(
        "-o", "--output", type=Path, metavar="FICHIER", help="écrit le résultat dans un fichier au lieu de l'écran"
    )
    out.add_argument("--force", action="store_true", help="autorise l'écrasement d'un fichier de sortie existant")
    out.add_argument("--all", action="store_true", dest="include_all", help="inclut aussi les ports fermés et filtrés")
    out.add_argument(
        "--fail-on",
        choices=tuple(_RISK_CHOICES),
        metavar="NIVEAU",
        help="code de sortie 1 si un port ouvert atteint ce risque : " + ", ".join(_RISK_CHOICES),
    )
    out.add_argument("--no-color", action="store_true", help="désactive les couleurs")
    out.add_argument("-q", "--quiet", action="store_true", help="n'affiche ni progression ni avertissement")

    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return parser


# ─────────────────────────────────────────────────────────────
# 3. Outils d'affichage
# ─────────────────────────────────────────────────────────────


def _use_utf8(stream: TextIO) -> None:
    """
    Force l'UTF-8 quand la sortie est redirigée (fichier, tube, autre programme).

    Sous Windows, une sortie redirigée utilise sinon l'encodage régional (cp1252) :
    certains caractères (→, …) font alors planter print(), et les accents arrivent
    abîmés dans PowerShell. Dans une vraie console, Python gère déjà l'Unicode.
    """
    reconfigure = getattr(stream, "reconfigure", None)
    if reconfigure is not None and not stream.isatty():
        try:
            reconfigure(encoding="utf-8", errors="replace")
        except (ValueError, OSError):
            pass


def _color_enabled(no_color_flag: bool) -> bool:
    """Couleurs seulement dans un vrai terminal et si l'utilisateur ne les a pas refusées."""
    # NO_COLOR : convention partagée par de nombreux outils (https://no-color.org)
    return not no_color_flag and "NO_COLOR" not in os.environ and sys.stdout.isatty()


class Progress:
    """Affiche « [ 120/400 ] 3 ouvert(s) » sur la sortie d'erreur, 10 fois par seconde au plus."""

    def __init__(self, total: int, enabled: bool) -> None:
        self.total, self.enabled = total, enabled
        self.done = self.open = 0
        self._last = 0.0

    def __call__(self, result: ScanResult) -> None:
        self.done += 1
        self.open += result.state.name == "OPEN"
        now = time.monotonic()
        if self.enabled and (now - self._last >= 0.1 or self.done == self.total):
            self._last = now
            sys.stderr.write(f"\r[ {self.done}/{self.total} ] {self.open} ouvert(s)")
            sys.stderr.flush()

    def finish(self) -> None:
        if self.enabled and self.done:
            sys.stderr.write("\n")


def _write_output(text: str, path: Path | None, force: bool) -> None:
    """Écrit à l'écran, ou dans un fichier UTF-8 (sans écraser sauf --force)."""
    if path is None:
        print(text)
        return
    # Mode « x » : création exclusive, échoue si le fichier existe déjà.
    # Évite d'écraser par erreur un rapport précédent (ou un fichier sans rapport avec le scan).
    mode = "w" if force else "x"
    # newline="" : le texte contient déjà des « \n » ; aucune conversion supplémentaire
    with path.open(mode, encoding="utf-8", newline="") as handle:
        handle.write(text if text.endswith("\n") else text + "\n")


# ─────────────────────────────────────────────────────────────
# 4. Point d'entrée
# ─────────────────────────────────────────────────────────────


def main(argv: list[str] | None = None, *, connector: Connector | None = None) -> int:
    """
    Point d'entrée de la commande « port-scanner ».

    connector : remplaçable dans les tests (simulation réseau) ; None = vraies connexions.
    """
    _use_utf8(sys.stdout)
    _use_utf8(sys.stderr)
    args = build_parser().parse_args(argv)
    warn = (lambda message: None) if args.quiet else (lambda message: print(message, file=sys.stderr))

    # ── Validation de toutes les saisies AVANT le moindre paquet envoyé ──
    try:
        ports = parse_ports(args.ports)
        targets = parse_targets(args.targets, allow_public=args.allow_public, max_hosts=args.max_hosts)
    except (PortSpecError, TargetError) as exc:
        print(f"Erreur : {exc}", file=sys.stderr)
        return EXIT_USAGE

    # Fichier de sortie : on vérifie AVANT le scan, pour ne pas perdre un long scan
    if args.output is not None and args.output.exists() and not args.force:
        print(f"Erreur : le fichier « {args.output} » existe déjà (utilisez --force pour l'écraser).", file=sys.stderr)
        return EXIT_USAGE

    public = [t for t in targets if classify(t.address) is Category.OTHER]
    if public:
        warn(
            f"Avertissement : {len(public)} cible(s) hors réseau privé (--allow-public). "
            "Assurez-vous de disposer d'une autorisation écrite."
        )

    progress = Progress(len(targets) * len(ports), enabled=not args.quiet and sys.stderr.isatty())
    started = datetime.now(UTC)
    clock = time.perf_counter()

    # ── Scan ─────────────────────────────────────────────────
    try:
        results = run_scan(
            targets,
            ports,
            timeout=args.timeout,
            concurrency=args.concurrency,
            grab_banners=args.banners,
            banner_timeout=args.banner_timeout,
            connector=connector,
            on_result=progress,
        )
    except ValueError as exc:  # bornes du moteur (scan trop volumineux…)
        progress.finish()
        print(f"Erreur : {exc}", file=sys.stderr)
        return EXIT_USAGE
    except KeyboardInterrupt:
        progress.finish()
        print("Scan interrompu.", file=sys.stderr)
        return EXIT_INTERRUPTED
    progress.finish()

    # ── Mise en forme ────────────────────────────────────────
    meta = ScanMeta(
        started_at=started.isoformat(timespec="seconds"),
        duration_s=round(time.perf_counter() - clock, 3),
        targets=len(targets),
        ports=len(ports),
        settings={
            "ports": args.ports,
            "timeout_s": args.timeout,
            "concurrency": args.concurrency,
            "banners": args.banners,
            "allow_public": args.allow_public,
        },
    )
    if args.format == "json":
        text = to_json(results, meta, args.include_all)
    elif args.format == "csv":
        text = to_csv(results, args.include_all)
    else:
        # Pas de couleurs dans un fichier : les codes ANSI y seraient illisibles
        color = args.output is None and _color_enabled(args.no_color)
        text = to_text(results, meta, args.include_all, color=color)

    try:
        _write_output(text, args.output, args.force)
    except FileExistsError:
        print(f"Erreur : le fichier « {args.output} » existe déjà (utilisez --force).", file=sys.stderr)
        return EXIT_ERROR
    except OSError as exc:
        print(f"Erreur : écriture impossible dans « {args.output} » : {exc.strerror or exc}", file=sys.stderr)
        return EXIT_ERROR

    # ── Code de sortie selon le seuil de risque ──────────────
    if args.fail_on is not None:
        highest = max_open_risk(results)
        if highest is not None and highest >= _RISK_CHOICES[args.fail_on]:
            return EXIT_RISK
    return EXIT_OK
