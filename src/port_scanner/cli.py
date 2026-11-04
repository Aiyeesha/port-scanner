"""
Interface en ligne de commande.

Étape 1 (ossature) : seules les options --help et --version existent.
Le scan lui-même arrivera aux étapes 2 à 5 ; d'ici là, la commande
affiche l'aide et se termine proprement.
"""

from __future__ import annotations   # annotations de type évaluées paresseusement

import argparse

from port_scanner import __version__


def build_parser() -> argparse.ArgumentParser:
    """Construit l'analyseur d'arguments (séparé de main() pour être testable)."""
    parser = argparse.ArgumentParser(
        prog="port-scanner",
        description=(
            "Scanner de ports TCP asynchrone. "
            "À n'utiliser que sur des systèmes dont vous êtes propriétaire "
            "ou pour lesquels vous disposez d'une autorisation écrite."
        ),
    )
    # action="version" affiche la chaîne puis quitte avec le code 0
    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {__version__}",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    """
    Point d'entrée de la commande.

    argv : liste des arguments ; None = arguments réels du terminal (sys.argv[1:]).
           Les tests passent leur propre liste, sans toucher au vrai terminal.
    Retourne le code de sortie (0 = succès).
    """
    parser = build_parser()
    parser.parse_args(argv)
    # Aucun scan disponible pour l'instant : on affiche l'aide.
    parser.print_help()
    return 0
