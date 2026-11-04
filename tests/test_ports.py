"""Tests de l'analyse des ports (aucun accès réseau)."""

import pytest

from port_scanner.ports import MAX_PORT, PRESETS, TOP_100, PortSpecError, parse_ports


# ── Formats valides ─────────────────────────────────────────
@pytest.mark.parametrize(
    ("spec", "attendu"),
    [
        ("22", (22,)),
        ("20-23", (20, 21, 22, 23)),
        ("443,22,80", (22, 80, 443)),  # trié
        ("22,22,20-22", (20, 21, 22)),  # dédoublonné
        (" 22 , 80 ", (22, 80)),  # espaces tolérés autour des éléments
        ("1", (1,)),  # borne basse
        ("65535", (65535,)),  # borne haute
        ("8080-8080", (8080,)),  # plage d'un seul port
    ],
)
def test_formats_valides(spec, attendu):
    assert parse_ports(spec) == attendu


def test_preregles_insensibles_a_la_casse():
    assert parse_ports("TOP100") == TOP_100
    assert parse_ports("Well-Known") == tuple(range(1, 1024))


def test_preregle_all_couvre_tous_les_ports():
    ports = parse_ports("all")
    assert len(ports) == MAX_PORT and ports[0] == 1 and ports[-1] == MAX_PORT


def test_top100_contient_100_ports_uniques_tries():
    assert len(TOP_100) == 100
    assert len(set(TOP_100)) == 100
    assert list(TOP_100) == sorted(TOP_100)


def test_combinaison_preregle_et_ports():
    ports = parse_ports("top100,31337")
    assert 31337 in ports and len(ports) == 101


# ── Saisies refusées ────────────────────────────────────────
@pytest.mark.parametrize(
    "spec",
    [
        "",  # vide
        "   ",  # espaces seuls
        "0",  # port 0 réservé
        "65536",  # au-delà de 16 bits
        "99999",
        "25-20",  # plage inversée
        "0-10",  # plage commençant à 0
        "22,,80",  # élément vide
        "22,",  # virgule finale
        "abc",  # texte
        "22abc",  # nombre suivi de texte
        "-22",  # signe négatif
        "+22",
        "20-",  # plage incomplète
        "20--25",
        "1e3",  # notation scientifique
        "123456",  # plus de 5 chiffres
        "２２",  # chiffres « pleine largeur » Unicode
        "top1000",  # préréglage inconnu
    ],
)
def test_saisies_refusees(spec):
    with pytest.raises(PortSpecError):
        parse_ports(spec)


def test_message_d_erreur_explicite():
    with pytest.raises(PortSpecError, match="hors limites"):
        parse_ports("70000")
    with pytest.raises(PortSpecError, match="inversée"):
        parse_ports("25-20")


def test_preregles_ne_contiennent_que_des_ports_valides():
    for nom, ports in PRESETS.items():
        assert all(1 <= p <= MAX_PORT for p in ports), nom
