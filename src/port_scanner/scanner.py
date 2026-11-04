"""
Moteur de scan TCP « connect » asynchrone.

Principe du scan « connect » : pour chaque couple (adresse, port), on demande au
système d'exploitation d'ouvrir une VRAIE connexion TCP (poignée de main complète
SYN → SYN/ACK → ACK), puis on la ferme aussitôt.

  - connexion acceptée            → OUVERT  (un service écoute)
  - connexion refusée (RST reçu)  → FERMÉ   (la machine répond, mais rien n'écoute)
  - aucune réponse avant le délai → FILTRÉ  (paquets probablement bloqués par un pare-feu)

Contrairement au scan « SYN » de Nmap, ce mode ne demande aucun droit administrateur,
mais il est plus visible : chaque connexion ouverte peut apparaître dans les journaux
du service visé. C'est précisément ce que l'étape 7 (détection) exploitera.

Asynchrone : asyncio mène des centaines de tentatives en parallèle dans UN SEUL thread.
Pendant qu'une connexion attend sa réponse, la boucle d'événements avance sur les autres.
"""

from __future__ import annotations

import asyncio
import contextlib
import enum
import errno
import itertools
import time
from collections.abc import Awaitable, Callable, Iterator, Sequence
from dataclasses import dataclass

from port_scanner.targets import Target

# ─────────────────────────────────────────────────────────────
# 1. Paramètres par défaut et bornes
# ─────────────────────────────────────────────────────────────

DEFAULT_TIMEOUT = 1.0          # secondes d'attente maximale par tentative
DEFAULT_CONCURRENCY = 100      # tentatives simultanées
MAX_CONCURRENCY = 500          # plafond : Linux limite souvent un processus à 1024 fichiers ouverts
MAX_TIMEOUT = 30.0             # au-delà, un scan devient inutilement long
MAX_PROBES = 262_144           # 4 × 65 536 tentatives : borne la mémoire et la durée d'un scan

# Délai maximal accordé à la fermeture propre d'une connexion ouverte
_CLOSE_TIMEOUT = 1.0

# Codes d'erreur « connexion refusée » selon le système :
# ECONNREFUSED (POSIX), 10061 (Winsock WSAECONNREFUSED), 1225 (Windows ERROR_CONNECTION_REFUSED)
_REFUSED_ERRNOS = {errno.ECONNREFUSED}
_REFUSED_WINERRORS = {10061, 1225}


class PortState(enum.Enum):
    """État d'un port après une tentative de connexion."""

    OPEN = "ouvert"
    CLOSED = "fermé"
    FILTERED = "filtré"


@dataclass(frozen=True)
class ScanResult:
    """
    Résultat d'une tentative.

    latency_ms : durée jusqu'à la réponse (ouvert ou fermé) ; None si aucune réponse.
    error      : détail technique quand l'état vient d'une erreur réseau inattendue.
    """

    target: Target
    port: int
    state: PortState
    latency_ms: float | None = None
    error: str | None = None


# Signature d'un « connecteur » : (hôte, port) → (lecteur, écrivain) asyncio.
# Par défaut asyncio.open_connection ; les tests en injectent de faux pour simuler
# un pare-feu ou une erreur réseau sans toucher au réseau.
Connector = Callable[[str, int], Awaitable[tuple[asyncio.StreamReader, asyncio.StreamWriter]]]
# Fonction appelée à chaque résultat (pour afficher une progression, par exemple)
ResultCallback = Callable[[ScanResult], None]


# ─────────────────────────────────────────────────────────────
# 2. Validation des paramètres
# ─────────────────────────────────────────────────────────────

def validate_settings(
    targets: Sequence[Target], ports: Sequence[int], timeout: float, concurrency: int
) -> None:
    """Lève ValueError (message destiné à l'utilisateur) si un paramètre est hors bornes."""
    if not targets:
        raise ValueError("Aucune cible à scanner.")
    if not ports:
        raise ValueError("Aucun port à scanner.")
    # « not 0 < x » rejette aussi NaN, qui échoue à toute comparaison
    if not 0 < timeout <= MAX_TIMEOUT:
        raise ValueError(f"Délai invalide : {timeout} s (attendu : supérieur à 0 et au plus {MAX_TIMEOUT} s).")
    if not 1 <= concurrency <= MAX_CONCURRENCY:
        raise ValueError(f"Concurrence invalide : {concurrency} (attendu : 1 à {MAX_CONCURRENCY}).")
    probes = len(targets) * len(ports)
    if probes > MAX_PROBES:
        raise ValueError(
            f"Scan trop volumineux : {probes} tentatives ({len(targets)} cibles × {len(ports)} ports), "
            f"maximum {MAX_PROBES}. Réduisez la plage d'adresses ou la liste de ports."
        )


# ─────────────────────────────────────────────────────────────
# 3. Une tentative de connexion
# ─────────────────────────────────────────────────────────────

def _is_refused(exc: OSError) -> bool:
    """Vrai si l'erreur signifie « connexion refusée », quel que soit le système."""
    return (
        isinstance(exc, ConnectionRefusedError)
        or exc.errno in _REFUSED_ERRNOS
        or getattr(exc, "winerror", None) in _REFUSED_WINERRORS
    )


async def _close_quietly(writer: asyncio.StreamWriter) -> None:
    """Ferme une connexion ouverte sans jamais bloquer ni lever d'exception."""
    writer.close()
    # suppress : une connexion déjà coupée par l'autre côté n'est pas une erreur du scan
    with contextlib.suppress(Exception):
        async with asyncio.timeout(_CLOSE_TIMEOUT):
            await writer.wait_closed()


async def probe(target: Target, port: int, timeout: float, connector: Connector) -> ScanResult:
    """Tente UNE connexion TCP et renvoie l'état observé."""
    start = time.perf_counter()

    def elapsed_ms() -> float:
        return round((time.perf_counter() - start) * 1000, 2)

    try:
        # asyncio.timeout (Python 3.11+) annule la tentative si elle dépasse le délai
        async with asyncio.timeout(timeout):
            _reader, writer = await connector(str(target.address), port)
    # ⚠️ L'ordre des « except » compte : TimeoutError et ConnectionRefusedError
    # sont des SOUS-CLASSES d'OSError ; elles doivent donc être traitées avant lui.
    except TimeoutError:
        return ScanResult(target, port, PortState.FILTERED)
    except OSError as exc:
        if _is_refused(exc):
            return ScanResult(target, port, PortState.CLOSED, latency_ms=elapsed_ms())
        # Autres erreurs (hôte injoignable, réseau inaccessible…) : aucune preuve
        # qu'un service écoute ou non → « filtré », avec le détail pour le diagnostic.
        detail = exc.strerror or exc.__class__.__name__
        return ScanResult(target, port, PortState.FILTERED, error=detail)

    latency = elapsed_ms()
    await _close_quietly(writer)
    return ScanResult(target, port, PortState.OPEN, latency_ms=latency)


# ─────────────────────────────────────────────────────────────
# 4. Le scan complet
# ─────────────────────────────────────────────────────────────

async def scan(
    targets: Sequence[Target],
    ports: Sequence[int],
    *,
    timeout: float = DEFAULT_TIMEOUT,
    concurrency: int = DEFAULT_CONCURRENCY,
    connector: Connector | None = None,
    on_result: ResultCallback | None = None,
) -> list[ScanResult]:
    """
    Scanne tous les couples (cible, port) et renvoie les résultats triés
    par cible (dans l'ordre fourni) puis par port.

    Architecture « pool de travailleurs » : exactement « concurrency » coroutines
    piochent les tentatives une à une dans un itérateur partagé. Le nombre de
    connexions simultanées est ainsi BORNÉ, et la mémoire aussi : les couples
    (cible, port) sont générés au fil de l'eau, jamais tous créés d'avance.
    """
    validate_settings(targets, ports, timeout, concurrency)
    connect = connector or asyncio.open_connection

    # Index de chaque cible pour reconstituer l'ordre final
    order = {target.address: index for index, target in enumerate(targets)}
    # product() génère (cible, port) paresseusement. Partager un itérateur entre
    # coroutines est sûr avec asyncio : un seul thread, et next() ne contient aucun « await ».
    jobs: Iterator[tuple[Target, int]] = itertools.product(targets, ports)
    results: list[ScanResult] = []

    async def worker() -> None:
        for target, port in jobs:
            result = await probe(target, port, timeout, connect)
            results.append(result)
            if on_result is not None:
                on_result(result)

    # TaskGroup (Python 3.11+) : si un travailleur plante, les autres sont annulés
    # proprement et l'erreur remonte — aucune tâche « orpheline ».
    workers = min(concurrency, len(targets) * len(ports))
    async with asyncio.TaskGroup() as group:
        for _ in range(workers):
            group.create_task(worker())

    results.sort(key=lambda r: (order[r.target.address], r.port))
    return results


def run_scan(targets: Sequence[Target], ports: Sequence[int], **options) -> list[ScanResult]:
    """Version synchrone de scan(), pour un appel depuis du code non asynchrone (la CLI)."""
    return asyncio.run(scan(targets, ports, **options))
