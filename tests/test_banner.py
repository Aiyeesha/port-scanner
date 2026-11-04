"""
Tests de la lecture et du nettoyage des bannières.

Le nettoyage est critique : une bannière vient de la machine scannée,
elle doit être traitée comme une donnée hostile.
"""

import asyncio
import time

import pytest

from port_scanner.banner import MAX_BANNER_CHARS, sanitize
from port_scanner.scanner import PortState, run_scan, scan
from port_scanner.targets import parse_targets

LOCAL = parse_targets(["127.0.0.1"])


# ── Nettoyage (fonction pure) ───────────────────────────────
@pytest.mark.parametrize(
    ("brut", "attendu"),
    [
        (b"SSH-2.0-OpenSSH_9.6\r\n", "SSH-2.0-OpenSSH_9.6"),          # fin de ligne retirée
        (b"220 mail ESMTP\r\n250 OK", "220 mail ESMTP\\r\\n250 OK"),  # sauts internes visibles
        (b"\x1b[31mROUGE\x1b[0m", "\\x1b[31mROUGE\\x1b[0m"),         # séquence ANSI neutralisée
        (b"\x1b]0;titre\x07", "\\x1b]0;titre\\x07"),                  # changement de titre du terminal
        (b"a\x00b", "a\\x00b"),                                       # octet nul
        (b"a\x7fb", "a\\x7fb"),                                       # DEL
        ("a\u009bb".encode(), "a\\x9bb"),                             # CSI C1 (équivalent d'ESC [)
        ("admin‮gnp.exe".encode(), "admin\\u202egnp.exe"),       # inversion bidi (Trojan Source)
        ("a​b".encode(), "a\\u200bb"),                           # espace de largeur nulle
        (b"caf\xc3\xa9", "café"),                                     # UTF-8 valide conservé
        (b"bad\xff\xfe", "bad��"),                          # UTF-8 invalide → �
        (b"  \r\n ", ""),                                             # rien d'utile
    ],
)
def test_sanitize(brut, attendu):
    assert sanitize(brut) == attendu


def test_sanitize_tronque():
    texte = sanitize(b"A" * 5000)
    assert len(texte) == MAX_BANNER_CHARS and texte.endswith("…")


def test_sanitize_ne_produit_que_des_caracteres_imprimables():
    tous_les_octets = bytes(range(256))
    assert sanitize(tous_les_octets, max_chars=10_000).isprintable()


# ── Lecture réelle sur la boucle locale ─────────────────────
async def banner_server(payload, delay=0.0):
    """Serveur local qui envoie « payload » après « delay » secondes."""
    async def handle(reader, writer):
        if delay:
            await asyncio.sleep(delay)
        if payload:
            writer.write(payload)
            await writer.drain()
        await reader.read()      # attend que le scanner ferme
        writer.close()

    server = await asyncio.start_server(handle, "127.0.0.1", 0)
    return server, server.sockets[0].getsockname()[1]


def scan_banner(payload, delay=0.0, **options):
    async def main():
        server, port = await banner_server(payload, delay)
        async with server:
            [result] = await scan(LOCAL, [port], timeout=2.0, **options)
            return result
    return asyncio.run(main())


def test_banniere_lue_si_demandee():
    result = scan_banner(b"SSH-2.0-Test_1.0\r\n", grab_banners=True)
    assert result.state is PortState.OPEN
    assert result.banner == "SSH-2.0-Test_1.0"


def test_banniere_ignoree_par_defaut():
    assert scan_banner(b"SSH-2.0-Test_1.0\r\n").banner is None


def test_banniere_malveillante_neutralisee():
    result = scan_banner(b"\x1b[2J\x1b[31mPWNED\x07", grab_banners=True)
    assert result.banner == "\\x1b[2J\\x1b[31mPWNED\\x07"
    assert "\x1b" not in result.banner


def test_service_silencieux_borne_par_le_delai():
    debut = time.perf_counter()
    result = scan_banner(b"", grab_banners=True, banner_timeout=0.3)
    assert result.state is PortState.OPEN and result.banner is None
    assert time.perf_counter() - debut < 2.0


def test_banniere_enorme_lue_partiellement():
    result = scan_banner(b"X" * 200_000, grab_banners=True)
    assert len(result.banner) <= MAX_BANNER_CHARS


@pytest.mark.parametrize("delai", [0, -1, 11])
def test_delai_de_banniere_invalide(delai):
    with pytest.raises(ValueError, match="bannière"):
        run_scan(LOCAL, [80], grab_banners=True, banner_timeout=delai)
