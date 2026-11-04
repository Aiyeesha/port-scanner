"""
Point d'entrée « python -m port_scanner ».

Permet de lancer l'outil même si la commande « port-scanner » n'est pas
dans le PATH (par exemple hors de l'environnement virtuel activé).
"""

import sys

from port_scanner.cli import main

# sys.exit() transmet le code de retour de main() au système d'exploitation :
# c'est ce code que lisent les scripts et la CI.
sys.exit(main())
