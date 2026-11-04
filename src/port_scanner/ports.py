"""
Analyse de la liste des ports à scanner.

Transforme une saisie humaine comme « 22,80,443 », « 20-25 » ou « top100 »
en un tuple de numéros de port triés et sans doublon.

Principe de sécurité : on VALIDE STRICTEMENT toute saisie (liste blanche de formats).
Ce qui n'est pas explicitement reconnu est refusé avec un message clair, au lieu
d'être « deviné » — une saisie ambiguë ne doit jamais élargir un scan par surprise.
"""

from __future__ import annotations

import re

# ─────────────────────────────────────────────────────────────
# 1. Bornes et préréglages
# ─────────────────────────────────────────────────────────────

# Un port TCP est codé sur 16 bits : 0 à 65535. Le port 0 est réservé
# (il signifie « choisis un port libre » côté système) : on ne le scanne pas.
MIN_PORT = 1
MAX_PORT = 65535

# Sélection de 100 ports TCP parmi les plus fréquemment ouverts
# (services web, accès distant, messagerie, bases de données, partage de fichiers…).
TOP_100: tuple[int, ...] = (
    7, 9, 13, 21, 22, 23, 25, 26, 37, 53, 79, 80, 81, 88, 106, 110, 111, 113, 119, 135,
    139, 143, 144, 179, 199, 389, 427, 443, 444, 445, 465, 513, 514, 515, 543, 544, 548,
    554, 587, 631, 646, 873, 990, 993, 995, 1025, 1026, 1027, 1028, 1029, 1110, 1433,
    1720, 1723, 1755, 1900, 2000, 2001, 2049, 2121, 2717, 3000, 3128, 3306, 3389, 3986,
    4899, 5000, 5009, 5051, 5060, 5101, 5190, 5357, 5432, 5631, 5666, 5800, 5900, 6000,
    6001, 6646, 7070, 8000, 8008, 8009, 8080, 8081, 8443, 8888, 9100, 9999, 10000, 32768,
    49152, 49153, 49154, 49155, 49156, 49157,
)

# Noms de préréglages acceptés (insensibles à la casse) → ports correspondants.
PRESETS: dict[str, tuple[int, ...]] = {
    "top100": TOP_100,
    # « well-known » : les ports « système » attribués par l'IANA (1 à 1023)
    "well-known": tuple(range(1, 1024)),
    "all": tuple(range(MIN_PORT, MAX_PORT + 1)),
}

# ─────────────────────────────────────────────────────────────
# 2. Formats reconnus pour un élément de la liste
# ─────────────────────────────────────────────────────────────
# fullmatch() impose que TOUTE la chaîne corresponde : « 22abc » est refusé.
# {1,5} limite la longueur : impossible de faire convertir un nombre géant.
# [0-9] et non \d : en Python, \d accepte TOUS les chiffres Unicode
# (« ２２ » en pleine largeur, chiffres arabes-indiens…) et int() les convertit.
_SINGLE = re.compile(r"[0-9]{1,5}")
_RANGE = re.compile(r"([0-9]{1,5})-([0-9]{1,5})")


class PortSpecError(ValueError):
    """Saisie de ports invalide. Le message est destiné à l'utilisateur final."""


def _check_bounds(port: int, token: str) -> int:
    """Vérifie qu'un numéro est dans [1, 65535] ; renvoie le numéro s'il est valide."""
    if not MIN_PORT <= port <= MAX_PORT:
        raise PortSpecError(
            f"Port hors limites dans « {token} » : {port} "
            f"(valeurs autorisées : {MIN_PORT} à {MAX_PORT})."
        )
    return port


def parse_ports(spec: str) -> tuple[int, ...]:
    """
    Convertit une saisie de ports en tuple trié et sans doublon.

    Formats acceptés, combinables avec des virgules :
      - un port :          « 22 »
      - une plage incluse : « 20-25 »  (début ≤ fin)
      - un préréglage :     « top100 », « well-known », « all »

    Exemple : parse_ports("443, 20-22,top100") → (7, 9, 13, 20, 21, 22, …)

    Lève PortSpecError si un élément est vide, mal formé ou hors limites.
    """
    # ── Saisie vide ou composée uniquement d'espaces ────────
    if not spec or not spec.strip():
        raise PortSpecError("Aucun port indiqué.")

    ports: set[int] = set()   # un ensemble élimine naturellement les doublons

    # ── Traitement de chaque élément séparé par une virgule ─
    for raw in spec.split(","):
        token = raw.strip()

        # « 22,,80 » ou « 22, » : élément vide → probablement une faute de frappe
        if not token:
            raise PortSpecError(f"Élément vide dans la liste de ports « {spec} ».")

        # Préréglage nommé (comparaison insensible à la casse)
        preset = PRESETS.get(token.lower())
        if preset is not None:
            ports.update(preset)
            continue

        # Port isolé
        if _SINGLE.fullmatch(token):
            ports.add(_check_bounds(int(token), token))
            continue

        # Plage « début-fin »
        match = _RANGE.fullmatch(token)
        if match:
            start = _check_bounds(int(match.group(1)), token)
            end = _check_bounds(int(match.group(2)), token)
            if start > end:
                raise PortSpecError(
                    f"Plage inversée « {token} » : le début doit être inférieur ou égal à la fin."
                )
            ports.update(range(start, end + 1))
            continue

        # Aucun format reconnu : refus explicite (jamais de « devinette »)
        noms = ", ".join(sorted(PRESETS))
        raise PortSpecError(
            f"Élément de port non reconnu : « {token} ». "
            f"Formats acceptés : 22, 20-25, ou un préréglage ({noms})."
        )

    # Tri croissant : ordre de scan prévisible et sorties reproductibles
    return tuple(sorted(ports))
