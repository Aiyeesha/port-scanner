"""
Tests du moteur de scan.

- Les états OUVERT et FERMÉ sont testés sur de VRAIS sockets, uniquement sur
  la boucle locale (127.0.0.1 / ::1) : rien ne sort de la machine.
- L'état FILTRÉ et les erreurs réseau sont simulés avec de faux « connecteurs »,
  car on ne peut pas créer un pare-feu dans un test.

pytest n'exécute pas nativement les fonctions « async » : chaque test lance
sa propre boucle d'événements avec asyncio.run().
"""

import asyncio
import errno
import socket

import pytest

from port_scanner.scanner import (
    MAX_CONCURRENCY,
    MAX_PROBES,
    PortState,
    run_scan,
    scan,
)
from port_scanner.targets import parse_targets

LOCAL = parse_targets(["127.0.0.1"])

# Windows réessaie la connexion après un refus sur la boucle locale (~2 s) :
# on laisse donc large pour que « fermé » ne soit pas confondu avec « filtré ».
CLOSED_TIMEOUT = 5.0


# ── Outils de test ──────────────────────────────────────────
def free_port(host="127.0.0.1", family=socket.AF_INET):
    """Réserve un port libre auprès du système, puis le libère : il est alors fermé."""
    with socket.socket(family, socket.SOCK_STREAM) as s:
        s.bind((host, 0))
        return s.getsockname()[1]


async def start_server(host="127.0.0.1"):
    """
    Démarre un petit serveur TCP local sur un port libre.
    Renvoie (serveur, port, événement « une connexion a été fermée par le client »).
    """
    closed = asyncio.Event()

    async def handle(reader, writer):
        await reader.read()          # attend la fin de flux (EOF) envoyée par le scanner
        closed.set()
        writer.close()

    server = await asyncio.start_server(handle, host, 0)
    port = server.sockets[0].getsockname()[1]
    return server, port, closed


def connector_raising(exc):
    """Faux connecteur qui lève immédiatement l'exception donnée."""
    async def connect(host, port):
        raise exc
    return connect


async def never_answers(host, port):
    """Faux connecteur qui n'obtient jamais de réponse (pare-feu qui ignore les paquets)."""
    await asyncio.sleep(3600)


# ── États réels sur la boucle locale ────────────────────────
def test_port_ouvert_detecte_et_connexion_refermee():
    async def main():
        server, port, closed = await start_server()
        async with server:
            [result] = await scan(LOCAL, [port], timeout=2.0)
            # Le scanner doit refermer sa connexion : le serveur reçoit la fin de flux
            await asyncio.wait_for(closed.wait(), timeout=2.0)
            return result

    result = asyncio.run(main())
    assert result.state is PortState.OPEN
    assert result.latency_ms is not None and result.latency_ms >= 0
    assert result.error is None


def test_port_ferme_detecte():
    [result] = run_scan(LOCAL, [free_port()], timeout=CLOSED_TIMEOUT)
    assert result.state is PortState.CLOSED
    assert result.latency_ms is not None


def test_plusieurs_ports_resultats_tries():
    async def main():
        server, port, _ = await start_server()
        async with server:
            ferme = free_port()
            return port, ferme, await scan(LOCAL, [ferme, port], timeout=CLOSED_TIMEOUT)

    ouvert, ferme, results = asyncio.run(main())
    assert [r.port for r in results] == sorted([ouvert, ferme])
    etats = {r.port: r.state for r in results}
    assert etats == {ouvert: PortState.OPEN, ferme: PortState.CLOSED}


def test_ipv6_boucle_locale():
    if not socket.has_ipv6:
        pytest.skip("IPv6 indisponible sur cette machine")

    async def main():
        try:
            server, port, _ = await start_server("::1")
        except OSError:
            pytest.skip("Impossible d'écouter sur ::1")
        async with server:
            return await scan(parse_targets(["::1"]), [port], timeout=2.0)

    [result] = asyncio.run(main())
    assert result.state is PortState.OPEN


# ── États simulés ───────────────────────────────────────────
def test_absence_de_reponse_donne_filtre():
    [result] = run_scan(LOCAL, [80], timeout=0.05, connector=never_answers)
    assert result.state is PortState.FILTERED
    assert result.latency_ms is None


@pytest.mark.parametrize(
    "exc",
    [
        ConnectionRefusedError(),
        OSError(errno.ECONNREFUSED, "refusé"),
        # Codes Windows : 10061 (Winsock) et 1225 (ERROR_CONNECTION_REFUSED)
        type("WinErr", (OSError,), {"winerror": 10061})(),
        type("WinErr", (OSError,), {"winerror": 1225})(),
    ],
)
def test_toutes_les_formes_de_refus_donnent_ferme(exc):
    [result] = run_scan(LOCAL, [80], connector=connector_raising(exc))
    assert result.state is PortState.CLOSED


def test_hote_injoignable_donne_filtre_avec_detail():
    exc = OSError(errno.EHOSTUNREACH, "No route to host")
    [result] = run_scan(LOCAL, [80], connector=connector_raising(exc))
    assert result.state is PortState.FILTERED
    assert result.error == "No route to host"


def test_erreur_inattendue_non_reseau_remonte():
    # Un bug (ici ZeroDivisionError) ne doit PAS être maquillé en « filtré »
    with pytest.raises(ExceptionGroup):
        run_scan(LOCAL, [80], connector=connector_raising(ZeroDivisionError()))


# ── Concurrence et ordre ────────────────────────────────────
def test_concurrence_bornee():
    en_cours = 0
    maximum = 0

    async def compte(host, port):
        nonlocal en_cours, maximum
        en_cours += 1
        maximum = max(maximum, en_cours)
        await asyncio.sleep(0.01)
        en_cours -= 1
        raise ConnectionRefusedError()

    results = run_scan(LOCAL, list(range(1, 201)), concurrency=7, connector=compte)
    assert len(results) == 200
    assert maximum == 7          # jamais plus de 7 tentatives simultanées


def test_ordre_cibles_puis_ports():
    cibles = parse_targets(["127.0.0.3", "127.0.0.2"])
    results = run_scan(cibles, [443, 22], connector=connector_raising(ConnectionRefusedError()))
    assert [(str(r.target.address), r.port) for r in results] == [
        ("127.0.0.3", 22), ("127.0.0.3", 443), ("127.0.0.2", 22), ("127.0.0.2", 443),
    ]


def test_rappel_appele_pour_chaque_resultat():
    vus = []
    run_scan(LOCAL, [1, 2, 3], connector=connector_raising(ConnectionRefusedError()), on_result=vus.append)
    assert sorted(r.port for r in vus) == [1, 2, 3]


# ── Validation des paramètres ───────────────────────────────
@pytest.mark.parametrize(
    "options",
    [
        {"timeout": 0},
        {"timeout": -1},
        {"timeout": float("nan")},
        {"timeout": 31},
        {"concurrency": 0},
        {"concurrency": MAX_CONCURRENCY + 1},
    ],
)
def test_parametres_invalides_refuses(options):
    with pytest.raises(ValueError):
        run_scan(LOCAL, [80], **options)


def test_listes_vides_refusees():
    with pytest.raises(ValueError, match="cible"):
        run_scan([], [80])
    with pytest.raises(ValueError, match="port"):
        run_scan(LOCAL, [])


def test_scan_trop_volumineux_refuse_avant_toute_connexion():
    cibles = parse_targets(["127.0.0.0/29"])          # 6 adresses
    ports = list(range(1, 65536))                     # 6 × 65 535 > MAX_PROBES

    async def interdit(host, port):
        raise AssertionError("aucune connexion ne doit être tentée")

    with pytest.raises(ValueError, match="trop volumineux"):
        run_scan(cibles, ports, connector=interdit)
    assert len(cibles) * len(ports) > MAX_PROBES
