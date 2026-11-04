"""Tests de l'ossature de la ligne de commande."""

import pytest

from port_scanner import __version__
from port_scanner.cli import main


def test_version_affiche_le_numero_et_quitte_avec_0(capsys):
    # argparse termine le programme via SystemExit après --version
    with pytest.raises(SystemExit) as fin:
        main(["--version"])
    assert fin.value.code == 0
    assert __version__ in capsys.readouterr().out


def test_sans_argument_affiche_l_aide(capsys):
    assert main([]) == 0
    sortie = capsys.readouterr().out
    assert "usage: port-scanner" in sortie
    # L'avertissement légal doit toujours figurer dans l'aide
    assert "autorisation" in sortie


def test_option_inconnue_est_refusee():
    # argparse renvoie le code 2 pour une erreur d'utilisation
    with pytest.raises(SystemExit) as fin:
        main(["--option-qui-n-existe-pas"])
    assert fin.value.code == 2
