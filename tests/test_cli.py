"""
Tests de la ligne de commande.

Le réseau est simulé par un faux « connecteur » (paramètre connector de main),
sauf dans le test de bout en bout qui scanne un vrai serveur sur 127.0.0.1.
"""

import asyncio
import json
import socket
import threading

import pytest

from port_scanner import __version__
from port_scanner.cli import EXIT_ERROR, EXIT_OK, EXIT_RISK, EXIT_USAGE, main

OPEN_PORTS = {22, 445}


async def fake_connector(host, port):
    """Simule une machine où seuls 22 et 445 sont ouverts."""
    if port not in OPEN_PORTS:
        raise ConnectionRefusedError()

    class Writer:
        def close(self):
            pass

        async def wait_closed(self):
            pass

    return asyncio.StreamReader(), Writer()


def run(argv, capsys):
    """Lance la CLI ; renvoie (code, sortie, erreurs)."""
    code = main(argv, connector=fake_connector)
    out, err = capsys.readouterr()
    return code, out, err


# ── Options de base ─────────────────────────────────────────
def test_version(capsys):
    with pytest.raises(SystemExit) as fin:
        main(["--version"])
    assert fin.value.code == 0
    assert __version__ in capsys.readouterr().out


def test_aide_contient_l_avertissement_legal(capsys):
    with pytest.raises(SystemExit):
        main(["--help"])
    assert "autorisation écrite" in capsys.readouterr().out


def test_cible_obligatoire(capsys):
    with pytest.raises(SystemExit) as fin:
        main([])
    assert fin.value.code == EXIT_USAGE


# ── Scan et formats ─────────────────────────────────────────
def test_sortie_texte(capsys):
    code, out, _ = run(["127.0.0.1", "-p", "21-23,445"], capsys)
    assert code == EXIT_OK
    assert "22/tcp" in out and "445/tcp" in out and "21/tcp" not in out
    assert "Recommandations" in out


def test_sortie_json(capsys):
    code, out, _ = run(["127.0.0.1", "-p", "21-23,445", "-f", "json"], capsys)
    doc = json.loads(out)
    assert code == EXIT_OK
    assert doc["summary"] == {"open": 2, "closed": 2, "filtered": 0}
    assert doc["settings"]["ports"] == "21-23,445"


def test_sortie_csv_avec_tous_les_ports(capsys):
    code, out, _ = run(["127.0.0.1", "-p", "21-23", "-f", "csv", "--all"], capsys)
    lines = out.strip().splitlines()
    assert lines[0].startswith("address,source,port,state")
    assert len(lines) == 4


# ── Codes de sortie et seuil de risque ──────────────────────
def test_fail_on_atteint(capsys):
    code, _, _ = run(["127.0.0.1", "-p", "445", "--fail-on", "high"], capsys)
    assert code == EXIT_RISK  # SMB = critique ≥ élevé


def test_fail_on_non_atteint(capsys):
    code, _, _ = run(["127.0.0.1", "-p", "22", "--fail-on", "high"], capsys)
    assert code == EXIT_OK  # SSH = moyen < élevé


@pytest.mark.parametrize(
    "argv",
    [
        ["127.0.0.1", "-p", "0"],
        ["127.0.0.1", "-p", "abc"],
        ["999.1.1.1"],
        ["8.8.8.8"],  # garde-fou
        ["10.0.0.0/16"],  # au-delà de --max-hosts par défaut
    ],
)
def test_erreurs_de_saisie(argv, capsys):
    code, out, err = run(argv, capsys)
    assert code == EXIT_USAGE
    assert err.startswith("Erreur :") and out == ""


@pytest.mark.parametrize(
    "argv",
    [
        ["127.0.0.1", "-t", "0"],
        ["127.0.0.1", "-t", "nan"],
        ["127.0.0.1", "-c", "0"],
        ["127.0.0.1", "-c", "501"],
        ["127.0.0.1", "--max-hosts", "0"],
        ["127.0.0.1", "-f", "xml"],
        ["127.0.0.1", "--fail-on", "extreme"],
    ],
)
def test_options_invalides(argv, capsys):
    with pytest.raises(SystemExit) as fin:
        main(argv, connector=fake_connector)
    assert fin.value.code == EXIT_USAGE


def test_allow_public_avertit(capsys):
    code, _, err = run(["192.0.2.10", "-p", "22", "--allow-public"], capsys)
    assert code == EXIT_OK
    assert "autorisation écrite" in err


def test_quiet_supprime_l_avertissement(capsys):
    _, _, err = run(["192.0.2.10", "-p", "22", "--allow-public", "-q"], capsys)
    assert err == ""


def test_scan_trop_volumineux(capsys):
    code, _, err = run(["127.0.0.0/28", "-p", "all"], capsys)
    assert code == EXIT_USAGE and "trop volumineux" in err


# ── Fichier de sortie ───────────────────────────────────────
def test_ecriture_dans_un_fichier(tmp_path, capsys):
    cible = tmp_path / "scan.json"
    code, out, _ = run(["127.0.0.1", "-p", "22", "-f", "json", "-o", str(cible)], capsys)
    assert code == EXIT_OK and out == ""
    assert json.loads(cible.read_text(encoding="utf-8"))["summary"]["open"] == 1


def test_fichier_existant_non_ecrase(tmp_path, capsys):
    cible = tmp_path / "rapport.txt"
    cible.write_text("ancien contenu", encoding="utf-8")
    code, _, err = run(["127.0.0.1", "-p", "22", "-o", str(cible)], capsys)
    assert code == EXIT_USAGE and "--force" in err
    assert cible.read_text(encoding="utf-8") == "ancien contenu"


def test_force_ecrase(tmp_path, capsys):
    cible = tmp_path / "rapport.txt"
    cible.write_text("ancien contenu", encoding="utf-8")
    code, _, _ = run(["127.0.0.1", "-p", "22", "-o", str(cible), "--force"], capsys)
    assert code == EXIT_OK and "22/tcp" in cible.read_text(encoding="utf-8")


def test_dossier_inexistant(tmp_path, capsys):
    code, _, err = run(["127.0.0.1", "-p", "22", "-o", str(tmp_path / "absent" / "x.txt")], capsys)
    assert code == EXIT_ERROR and "Erreur" in err


# ── Bout en bout sur un vrai serveur local ──────────────────
def test_bout_en_bout_avec_banniere(capsys):
    """Un serveur TCP réel sur 127.0.0.1 envoie une bannière ; la CLI doit la rapporter."""
    serveur = socket.create_server(("127.0.0.1", 0))
    port = serveur.getsockname()[1]

    def accepter():
        conn, _ = serveur.accept()
        with conn:
            conn.sendall(b"SSH-2.0-E2E_Test\r\n")
            conn.recv(1)  # attend la fermeture côté scanner

    fil = threading.Thread(target=accepter, daemon=True)
    fil.start()
    try:
        code = main(["127.0.0.1", "-p", str(port), "--banners", "-f", "json", "-q"])
    finally:
        fil.join(timeout=5)
        serveur.close()
    doc = json.loads(capsys.readouterr().out)
    assert code == EXIT_OK
    [r] = doc["results"]
    assert r["port"] == port and r["state"] == "open" and r["banner"] == "SSH-2.0-E2E_Test"
