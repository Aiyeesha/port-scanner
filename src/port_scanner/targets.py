"""
Analyse des cibles et garde-fou « réseaux privés ».

Transforme des saisies comme « 192.168.1.10 », « 10.0.0.0/30 », « ::1 » ou
« nas.local » en une liste d'adresses IP à scanner, APRÈS avoir vérifié
que chacune est autorisée.

Règle de sécurité par défaut (« secure by default ») :
  - boucle locale (127.0.0.0/8, ::1)          → autorisée ;
  - réseaux privés (RFC 1918, IPv6 ULA)       → autorisés ;
  - tout le reste (Internet public, lien local,
    CGNAT, plages de documentation…)          → refusé, sauf option explicite ;
  - adresses qui ne désignent pas UNE machine
    (multicast, non spécifiée, réservée…)      → toujours refusées.
"""

from __future__ import annotations

import enum
import ipaddress
import re
import socket
from collections.abc import Callable, Iterable
from dataclasses import dataclass

# Type commun aux adresses IPv4 et IPv6
IPAddress = ipaddress.IPv4Address | ipaddress.IPv6Address

# ─────────────────────────────────────────────────────────────
# 1. Constantes
# ─────────────────────────────────────────────────────────────

# Nombre maximal d'adresses par défaut : 1024 (soit un /22 en IPv4).
# Empêche qu'une faute de frappe (« /8 » au lieu de « /28 ») lance
# un scan de 16 millions d'adresses.
DEFAULT_MAX_HOSTS = 1024

# Réseaux privés, listés EXPLICITEMENT.
# On n'utilise pas « ip.is_private » de Python : cette propriété inclut aussi
# le lien local, les plages de documentation, etc., ce qui est trop large ici.
PRIVATE_NETWORKS: tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...] = (
    ipaddress.ip_network("10.0.0.0/8"),  # RFC 1918
    ipaddress.ip_network("172.16.0.0/12"),  # RFC 1918
    ipaddress.ip_network("192.168.0.0/16"),  # RFC 1918
    ipaddress.ip_network("fc00::/7"),  # RFC 4193 — adresses IPv6 locales uniques (ULA)
)

# Nom d'hôte valide (RFC 1123) : étiquettes de 1 à 63 caractères, lettres, chiffres
# et tirets, sans tiret au début ni à la fin, séparées par des points.
# Valider AVANT d'interroger le DNS évite d'envoyer n'importe quoi au résolveur.
_LABEL = r"(?!-)[A-Za-z0-9-]{1,63}(?<!-)"
_HOSTNAME = re.compile(rf"{_LABEL}(?:\.{_LABEL})*\.?")


class TargetError(ValueError):
    """Cible invalide ou refusée. Le message est destiné à l'utilisateur final."""


class Category(enum.Enum):
    """Catégorie de sécurité d'une adresse IP."""

    LOOPBACK = "boucle locale"
    PRIVATE = "réseau privé"
    OTHER = "hors réseau privé"  # public, lien local, CGNAT, documentation…
    FORBIDDEN = "adresse non scannable"  # multicast, non spécifiée, réservée…


@dataclass(frozen=True)
class Target:
    """
    Une adresse à scanner.

    address : l'adresse IP réellement contactée.
    source  : la saisie d'origine (utile à l'affichage, ex. « nas.local »).
    frozen=True rend l'objet immuable : il ne peut pas être modifié par erreur.
    """

    address: IPAddress
    source: str


# ─────────────────────────────────────────────────────────────
# 2. Classification d'une adresse
# ─────────────────────────────────────────────────────────────


def classify(address: IPAddress) -> Category:
    """Range une adresse dans une catégorie de sécurité."""
    # Une adresse IPv6 « mappée » (::ffff:10.0.0.1) désigne en réalité une
    # adresse IPv4 : on classe l'IPv4 sous-jacente, sinon le garde-fou
    # pourrait être contourné en écrivant une IP publique sous cette forme.
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped is not None:
        address = address.ipv4_mapped

    # Adresses qui ne désignent pas une machine précise : jamais scannées.
    if address.is_multicast or address.is_unspecified:
        return Category.FORBIDDEN
    # La boucle locale est testée AVANT « réservée » : en IPv6, ::1 appartient
    # au bloc ::/8 que Python marque comme réservé.
    if address.is_loopback:
        return Category.LOOPBACK
    # is_reserved couvre notamment 240.0.0.0/4, donc aussi 255.255.255.255
    if address.is_reserved:
        return Category.FORBIDDEN
    if any(address in network for network in PRIVATE_NETWORKS if network.version == address.version):
        return Category.PRIVATE
    return Category.OTHER


def _ensure_allowed(address: IPAddress, source: str, allow_public: bool) -> None:
    """Lève TargetError si l'adresse n'est pas autorisée par le garde-fou."""
    category = classify(address)
    if category is Category.FORBIDDEN:
        raise TargetError(f"Cible refusée « {source} » : {address} est une {category.value}.")
    if category is Category.OTHER and not allow_public:
        raise TargetError(
            f"Cible refusée « {source} » : {address} est {category.value}. "
            "Par défaut, seuls les réseaux privés et la boucle locale sont autorisés. "
            "Ne levez ce garde-fou que pour un système que vous possédez "
            "ou pour lequel vous avez une autorisation écrite."
        )


# ─────────────────────────────────────────────────────────────
# 3. Résolution DNS
# ─────────────────────────────────────────────────────────────

# Signature d'un résolveur : nom d'hôte → liste d'adresses IP (texte).
# Injectable : les tests fournissent un faux résolveur, sans aucun accès réseau.
Resolver = Callable[[str], list[str]]


def system_resolver(hostname: str) -> list[str]:
    """Résout un nom d'hôte avec le résolveur du système (IPv4 et IPv6)."""
    try:
        infos = socket.getaddrinfo(hostname, None, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise TargetError(f"Nom d'hôte introuvable : « {hostname} ».") from exc
    # info[4][0] = l'adresse IP ; dict.fromkeys dédoublonne en gardant l'ordre
    return list(dict.fromkeys(str(info[4][0]) for info in infos))


# ─────────────────────────────────────────────────────────────
# 4. Expansion d'une saisie en adresses
# ─────────────────────────────────────────────────────────────


def _expand_one(spec: str, resolver: Resolver, budget: int) -> list[IPAddress]:
    """
    Convertit UNE saisie en adresses, sans dépasser « budget » adresses.

    Ordre d'essai : adresse IP → réseau CIDR → nom d'hôte.
    """
    # ── Adresse IP seule ────────────────────────────────────
    try:
        return [ipaddress.ip_address(spec)]
    except ValueError:
        pass

    # ── Réseau CIDR (ex. 192.168.1.0/24) ────────────────────
    if "/" in spec:
        try:
            # strict=False accepte « 192.168.1.10/24 » et le ramène à 192.168.1.0/24
            network = ipaddress.ip_network(spec, strict=False)
        except ValueError as exc:
            raise TargetError(f"Réseau invalide : « {spec} ».") from exc
        # On compare la TAILLE avant de générer la moindre adresse :
        # un /64 IPv6 en contient 2^64, impossible à énumérer.
        if network.num_addresses > budget + 2:
            raise TargetError(
                f"Réseau trop grand « {spec} » : {network.num_addresses} adresses (maximum restant : {budget})."
            )
        # hosts() exclut l'adresse de réseau et de diffusion (sauf /31 et /32)
        return list(network.hosts())

    # ── Nom d'hôte ──────────────────────────────────────────
    # Un nom dont la dernière étiquette est numérique (« 127.1 », « 0x7f.1 », « 10.0.0.256 »)
    # n'est pas un vrai nom de domaine (RFC 3696 §2) : c'est une IP mal écrite.
    # Le résolveur du système l'interpréterait selon d'anciennes règles ambiguës
    # (« 127.1 » → 127.0.0.1) : on préfère la refuser clairement.
    if spec.rstrip(".").rsplit(".", 1)[-1].isdigit():
        raise TargetError(f"Adresse IP invalide : « {spec} ».")
    if len(spec) > 253 or not _HOSTNAME.fullmatch(spec):
        raise TargetError(f"Cible non reconnue : « {spec} » (ni IP, ni réseau CIDR, ni nom d'hôte valide).")
    addresses: list[IPAddress] = []
    for text in resolver(spec):
        try:
            addresses.append(ipaddress.ip_address(text.split("%")[0]))  # retire un éventuel %zone IPv6
        except ValueError as exc:
            raise TargetError(f"Réponse DNS invalide pour « {spec} » : {text!r}.") from exc
    if not addresses:
        raise TargetError(f"Aucune adresse trouvée pour « {spec} ».")
    return addresses


def parse_targets(
    specs: Iterable[str],
    *,
    allow_public: bool = False,
    max_hosts: int = DEFAULT_MAX_HOSTS,
    resolver: Resolver = system_resolver,
) -> list[Target]:
    """
    Convertit des saisies de cibles en liste de Target autorisées et sans doublon.

    specs        : saisies de l'utilisateur (IP, réseau CIDR ou nom d'hôte).
    allow_public : True = autorise les adresses hors réseau privé (option explicite).
    max_hosts    : nombre maximal d'adresses au total, toutes saisies confondues.
    resolver     : fonction de résolution DNS (remplaçable dans les tests).

    Le garde-fou est appliqué à CHAQUE adresse, y compris celles obtenues par DNS :
    un nom d'hôte qui pointe vers une IP publique est donc refusé lui aussi.
    """
    targets: dict[IPAddress, Target] = {}  # clé = adresse → dédoublonnage, ordre conservé

    for raw in specs:
        spec = raw.strip()
        if not spec:
            raise TargetError("Cible vide.")

        budget = max_hosts - len(targets)
        for address in _expand_one(spec, resolver, budget):
            _ensure_allowed(address, spec, allow_public)
            if address not in targets:
                targets[address] = Target(address=address, source=spec)
                if len(targets) > max_hosts:
                    raise TargetError(f"Trop de cibles : plus de {max_hosts} adresses au total.")

    if not targets:
        raise TargetError("Aucune cible indiquée.")
    return list(targets.values())
