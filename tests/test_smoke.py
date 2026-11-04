"""
Test de fumée (« smoke test ») : la vérification la plus simple possible.

Il confirme que le paquet est installé, importable, et que la version
installée correspond à celle du code.
"""

from importlib.metadata import version  # lit les métadonnées du paquet INSTALLÉ

import port_scanner


def test_le_paquet_expose_sa_version():
    assert port_scanner.__version__ == "1.0.0"


def test_la_version_installee_correspond_au_code():
    # Si ce test échoue : relancez « pip install -e ".[dev]" » après un changement de version.
    assert version("port-scanner") == port_scanner.__version__
