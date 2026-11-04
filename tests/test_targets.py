"""
Tests de l'analyse des cibles et du garde-fou.

Aucun test n'accède au réseau : la résolution DNS est remplacée par un
faux résolveur (dictionnaire), injecté via le paramètre « resolver ».
Les IP publiques utilisées sont des plages de DOCUMENTATION (RFC 5737 / 3849)
ou des adresses notoires, jamais contactées.
"""

import ipaddress

import pytest

from port_scanner.targets import (
    DEFAULT_MAX_HOSTS,
    Category,
    TargetError,
    classify,
    parse_targets,
)

# ── Faux résolveur DNS ──────────────────────────────────────
FAKE_DNS = {
    "nas.local": ["192.168.1.20"],
    "double.lan": ["10.0.0.5", "fd00::5"],
    "public.example": ["93.184.216.34"],
    "mixte.example": ["192.168.1.30", "8.8.8.8"],  # une réponse privée + une publique
    "vide.example": [],
    "corrompu.example": ["pas-une-ip"],
}


def fake_resolver(name):
    if name not in FAKE_DNS:
        raise TargetError(f"Nom d'hôte introuvable : « {name} ».")
    return FAKE_DNS[name]


def parse(*specs, **kwargs):
    """Raccourci : parse_targets avec le faux résolveur, renvoie les adresses en texte."""
    kwargs.setdefault("resolver", fake_resolver)
    return [str(t.address) for t in parse_targets(list(specs), **kwargs)]


# ── Classification ──────────────────────────────────────────
@pytest.mark.parametrize(
    ("ip", "categorie"),
    [
        ("127.0.0.1", Category.LOOPBACK),
        ("127.8.9.10", Category.LOOPBACK),  # tout 127.0.0.0/8
        ("::1", Category.LOOPBACK),
        ("10.1.2.3", Category.PRIVATE),
        ("172.16.0.1", Category.PRIVATE),
        ("172.31.255.254", Category.PRIVATE),
        ("192.168.0.1", Category.PRIVATE),
        ("fd12:3456::1", Category.PRIVATE),  # IPv6 ULA
        ("172.32.0.1", Category.OTHER),  # juste hors de 172.16.0.0/12
        ("8.8.8.8", Category.OTHER),  # public
        ("169.254.169.254", Category.OTHER),  # lien local (dont métadonnées cloud)
        ("100.64.0.1", Category.OTHER),  # CGNAT (RFC 6598)
        ("192.0.2.1", Category.OTHER),  # documentation (RFC 5737)
        ("fe80::1", Category.OTHER),  # IPv6 lien local
        ("2001:db8::1", Category.OTHER),  # IPv6 documentation
        ("224.0.0.1", Category.FORBIDDEN),  # multicast
        ("ff02::1", Category.FORBIDDEN),  # multicast IPv6
        ("0.0.0.0", Category.FORBIDDEN),  # non spécifiée
        ("::", Category.FORBIDDEN),
        ("240.0.0.1", Category.FORBIDDEN),  # réservée
        ("255.255.255.255", Category.FORBIDDEN),  # diffusion générale
    ],
)
def test_classification(ip, categorie):
    assert classify(ipaddress.ip_address(ip)) is categorie


def test_ipv6_mappee_est_classee_comme_l_ipv4_sous_jacente():
    # Contournement classique : écrire une IP publique sous forme IPv6 mappée
    assert classify(ipaddress.ip_address("::ffff:8.8.8.8")) is Category.OTHER
    assert classify(ipaddress.ip_address("::ffff:192.168.1.1")) is Category.PRIVATE
    with pytest.raises(TargetError):
        parse("::ffff:8.8.8.8")


# ── Formats acceptés ────────────────────────────────────────
def test_ip_seule():
    assert parse("192.168.1.10") == ["192.168.1.10"]


def test_reseau_cidr_exclut_reseau_et_diffusion():
    assert parse("192.168.1.0/30") == ["192.168.1.1", "192.168.1.2"]


def test_cidr_non_aligne_est_ramene_au_reseau():
    assert parse("192.168.1.10/30") == ["192.168.1.9", "192.168.1.10"]


def test_cidr_32_donne_une_adresse():
    assert parse("10.0.0.7/32") == ["10.0.0.7"]


def test_nom_d_hote_resolu_et_source_conservee():
    cibles = parse_targets(["nas.local"], resolver=fake_resolver)
    assert str(cibles[0].address) == "192.168.1.20"
    assert cibles[0].source == "nas.local"


def test_nom_d_hote_avec_plusieurs_adresses():
    assert parse("double.lan") == ["10.0.0.5", "fd00::5"]


def test_doublons_supprimes_en_gardant_l_ordre():
    assert parse("192.168.1.2", "192.168.1.0/30", "192.168.1.1") == ["192.168.1.2", "192.168.1.1"]


def test_espaces_autour_de_la_saisie_toleres():
    assert parse("  127.0.0.1  ") == ["127.0.0.1"]


# ── Garde-fou ───────────────────────────────────────────────
@pytest.mark.parametrize("cible", ["8.8.8.8", "169.254.169.254", "2001:db8::1", "public.example"])
def test_hors_reseau_prive_refuse_par_defaut(cible):
    with pytest.raises(TargetError, match="autorisation écrite"):
        parse(cible)


def test_hors_reseau_prive_accepte_avec_option_explicite():
    assert parse("8.8.8.8", allow_public=True) == ["8.8.8.8"]


def test_nom_d_hote_avec_une_seule_reponse_publique_est_refuse():
    # Toutes les adresses résolues sont contrôlées, pas seulement la première
    with pytest.raises(TargetError):
        parse("mixte.example")


@pytest.mark.parametrize("cible", ["224.0.0.1", "0.0.0.0", "255.255.255.255", "ff02::1"])
def test_adresses_non_scannables_refusees_meme_avec_option(cible):
    with pytest.raises(TargetError, match="non scannable"):
        parse(cible, allow_public=True)


# ── Limite de taille ────────────────────────────────────────
def test_reseau_trop_grand_refuse_avant_toute_enumeration():
    with pytest.raises(TargetError, match="trop grand"):
        parse("10.0.0.0/8")
    # Un /64 IPv6 (2^64 adresses) doit être refusé instantanément
    with pytest.raises(TargetError, match="trop grand"):
        parse("fd00::/64")


def test_limite_par_defaut_accepte_un_slash_22():
    assert len(parse("10.0.0.0/22")) == 1022
    assert DEFAULT_MAX_HOSTS == 1024


def test_limite_cumulee_sur_plusieurs_saisies():
    with pytest.raises(TargetError, match="Trop de cibles|trop grand"):
        parse("10.0.0.0/24", "10.0.1.0/24", max_hosts=300)


def test_limite_personnalisee():
    assert len(parse("192.168.1.0/29", max_hosts=6)) == 6
    with pytest.raises(TargetError):
        parse("192.168.1.0/29", max_hosts=5)


# ── Saisies refusées ────────────────────────────────────────
@pytest.mark.parametrize(
    "cible",
    [
        "",
        "   ",
        "192.168.1.256",  # octet hors limites
        "127.1",  # forme abrégée ambiguë
        "0x7f.1",  # forme hexadécimale ambiguë
        "10.0.0.0/33",  # préfixe invalide
        "192.168.1.0/abc",
        "-nas.local",  # tiret en tête d'étiquette
        "nas_local",  # underscore interdit
        "nas local",  # espace interne
        "a" * 64 + ".lan",  # étiquette de plus de 63 caractères
        "ｎａｓ.local",  # lettres pleine largeur Unicode
        "inconnu.example",  # non résolu
        "vide.example",  # résolu sans adresse
        "corrompu.example",  # réponse DNS invalide
    ],
)
def test_saisies_refusees(cible):
    with pytest.raises(TargetError):
        parse(cible)


def test_aucune_cible():
    with pytest.raises(TargetError, match="Aucune cible"):
        parse_targets([], resolver=fake_resolver)


def test_resolveur_systeme_non_appele_pour_une_ip(monkeypatch):
    # Une IP ne doit jamais déclencher de requête DNS
    def interdit(_name):
        raise AssertionError("le résolveur ne doit pas être appelé")

    assert [str(t.address) for t in parse_targets(["127.0.0.1"], resolver=interdit)] == ["127.0.0.1"]
