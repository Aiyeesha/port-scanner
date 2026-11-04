"""
Lecture et nettoyage des bannières.

Une « bannière » est le texte qu'un service envoie SPONTANÉMENT dès la connexion,
par exemple « SSH-2.0-OpenSSH_9.6 » ou « 220 mail.example ESMTP ».
Elle aide à confirmer le service et sa version (donc ses vulnérabilités connues).

Le scanner reste PASSIF : il lit, mais n'envoie rien. Conséquence assumée : les
services qui attendent que le client parle en premier (HTTP, TLS…) ne renvoient pas
de bannière.

⚠️ Sécurité : une bannière est une DONNÉE NON FIABLE fournie par la machine scannée.
Un serveur malveillant peut y placer :
  - des séquences d'échappement de terminal (ESC [ …) qui modifient l'affichage,
    voire déclenchent des comportements du terminal ;
  - des caractères Unicode invisibles ou de contrôle du sens d'écriture
    (attaque « Trojan Source ») qui maquillent le texte affiché ;
  - une quantité énorme de données pour saturer la mémoire.
D'où : taille de lecture bornée, délai court, et neutralisation de tout caractère
non imprimable AVANT tout affichage ou enregistrement.
"""

from __future__ import annotations

import asyncio

MAX_BANNER_BYTES = 1024        # octets lus au maximum
MAX_BANNER_CHARS = 200         # caractères conservés après nettoyage
DEFAULT_BANNER_TIMEOUT = 2.0   # secondes d'attente de la bannière
MAX_BANNER_TIMEOUT = 10.0

# Caractères de contrôle courants : rendus sous une forme lisible et inoffensive
_COMMON_ESCAPES = {"\n": "\\n", "\r": "\\r", "\t": "\\t"}


def sanitize(data: bytes, max_chars: int = MAX_BANNER_CHARS) -> str:
    """
    Convertit des octets reçus en texte SÛR à afficher.

    - décodage UTF-8 tolérant (octet invalide → caractère de remplacement « � ») ;
    - espaces et sauts de ligne retirés aux extrémités ;
    - tout caractère non imprimable (contrôle C0/C1, ESC, DEL, caractères invisibles
      ou bidirectionnels Unicode…) remplacé par son code échappé : \\x1b, \\u202e… ;
    - texte tronqué à max_chars, avec « … » pour signaler la troncature.
    """
    text = data.decode("utf-8", errors="replace").strip()
    parts: list[str] = []
    for char in text:
        # isprintable() est False pour toutes les catégories Unicode « Autre » (Cc, Cf…)
        # et « Séparateur » sauf l'espace ASCII : c'est exactement ce qu'il faut neutraliser.
        if char.isprintable():
            parts.append(char)
        elif char in _COMMON_ESCAPES:
            parts.append(_COMMON_ESCAPES[char])
        elif ord(char) < 0x100:
            parts.append(f"\\x{ord(char):02x}")
        else:
            parts.append(f"\\u{ord(char):04x}")
    safe = "".join(parts)
    if len(safe) > max_chars:
        safe = safe[: max_chars - 1] + "…"
    return safe


async def read_banner(
    reader: asyncio.StreamReader,
    timeout: float = DEFAULT_BANNER_TIMEOUT,
    limit: int = MAX_BANNER_BYTES,
) -> str | None:
    """
    Lit la bannière éventuelle d'une connexion déjà ouverte.

    Renvoie le texte nettoyé, ou None si le service n'a rien envoyé à temps,
    a fermé la connexion sans rien dire, ou si la connexion a été coupée.
    """
    try:
        # read(limit) rend dès que des octets arrivent (au plus « limit ») : une seule lecture,
        # la taille est donc bornée quoi que fasse le serveur.
        async with asyncio.timeout(timeout):
            data = await reader.read(limit)
    except (TimeoutError, OSError):
        return None
    text = sanitize(data)
    return text or None
