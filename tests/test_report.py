"""Tests de la mise en forme des résultats (texte, JSON, CSV)."""

import csv
import io
import json

from port_scanner.report import ScanMeta, max_open_risk, summary, to_csv, to_json, to_text
from port_scanner.scanner import PortState, ScanResult
from port_scanner.services import Risk
from port_scanner.targets import parse_targets

[HOST] = parse_targets(["127.0.0.1"])
META = ScanMeta(started_at="2026-11-04T20:00:00+00:00", duration_s=1.5, targets=1, ports=4)
RESULTS = [
    ScanResult(HOST, 22, PortState.OPEN, latency_ms=1.2, banner="SSH-2.0-Test"),
    ScanResult(HOST, 23, PortState.CLOSED, latency_ms=0.5),
    ScanResult(HOST, 445, PortState.OPEN, latency_ms=0.9),
    ScanResult(HOST, 8080, PortState.FILTERED, error="No route to host"),
]


def test_synthese_compte_tous_les_etats():
    assert summary(RESULTS) == {"open": 2, "closed": 1, "filtered": 1}


def test_risque_maximal_des_ports_ouverts():
    assert max_open_risk(RESULTS) is Risk.CRITICAL  # 445 SMB
    assert max_open_risk(RESULTS[1:2]) is None  # aucun ouvert


def test_json_structure_et_valeurs_stables():
    doc = json.loads(to_json(RESULTS, META))
    assert doc["tool"] == "port-scanner"
    assert doc["summary"] == {"open": 2, "closed": 1, "filtered": 1}
    assert [r["port"] for r in doc["results"]] == [22, 445]  # ouverts seulement par défaut
    ssh = doc["results"][0]
    assert ssh == {
        "address": "127.0.0.1",
        "source": "127.0.0.1",
        "port": 22,
        "state": "open",
        "service": "ssh",
        "risk": "medium",
        "latency_ms": 1.2,
        "banner": "SSH-2.0-Test",
        "error": None,
    }


def test_json_tous_les_resultats():
    doc = json.loads(to_json(RESULTS, META, include_all=True))
    assert [r["state"] for r in doc["results"]] == ["open", "closed", "open", "filtered"]


def test_csv_entete_et_lignes():
    rows = list(csv.DictReader(io.StringIO(to_csv(RESULTS, include_all=True))))
    assert len(rows) == 4
    assert rows[0]["service"] == "ssh" and rows[0]["risk"] == "medium"
    assert rows[3]["error"] == "No route to host"


def test_csv_neutralise_les_formules():
    # Bannière piégée : un tableur exécuterait la formule à l'ouverture du fichier
    for piege in ('=HYPERLINK("http://x")', "+1+1", "-2", "@SUM(A1)", "\tcmd"):
        result = ScanResult(HOST, 22, PortState.OPEN, banner=piege)
        [row] = csv.DictReader(io.StringIO(to_csv([result])))
        assert row["banner"] == "'" + piege


def test_csv_texte_normal_intact():
    result = ScanResult(HOST, 22, PortState.OPEN, banner="SSH-2.0-OpenSSH_9.6")
    [row] = csv.DictReader(io.StringIO(to_csv([result])))
    assert row["banner"] == "SSH-2.0-OpenSSH_9.6"


def test_texte_lisible_avec_recommandations_triees():
    text = to_text(RESULTS, META)
    assert "127.0.0.1" in text and "22/tcp" in text and "445/tcp" in text
    assert "23/tcp" not in text  # fermé masqué par défaut
    assert "2 ouvert(s), 1 fermé(s), 1 filtré(s)" in text
    # La recommandation la plus critique (SMB) vient avant SSH
    assert text.index("[critique] smb") < text.index("[moyen] ssh")
    assert "\033[" not in text  # pas de couleur par défaut


def test_texte_avec_couleurs():
    assert "\033[" in to_text(RESULTS, META, color=True)


def test_texte_sans_port_ouvert():
    assert "Aucun port ouvert" in to_text(RESULTS[1:2], META)


def test_nom_d_hote_affiche_a_cote_de_l_adresse():
    [cible] = parse_targets(["nas.local"], resolver=lambda _n: ["192.168.1.20"])
    text = to_text([ScanResult(cible, 22, PortState.OPEN)], META)
    assert "192.168.1.20 (nas.local)" in text
