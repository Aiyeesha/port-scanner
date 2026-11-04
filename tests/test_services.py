"""Tests de l'identification des services."""

import pytest

from port_scanner.ports import TOP_100
from port_scanner.scanner import PortState, ScanResult
from port_scanner.services import SERVICES, UNKNOWN, Risk, lookup
from port_scanner.targets import parse_targets


@pytest.mark.parametrize(
    ("port", "nom", "risque"),
    [
        (22, "ssh", Risk.MEDIUM),
        (23, "telnet", Risk.CRITICAL),
        (80, "http", Risk.LOW),
        (135, "msrpc", Risk.HIGH),
        (445, "smb", Risk.CRITICAL),
        (3389, "rdp", Risk.CRITICAL),
        (6379, "redis", Risk.CRITICAL),
    ],
)
def test_services_connus(port, nom, risque):
    info = lookup(port)
    assert info.name == nom and info.risk is risque


def test_port_inconnu():
    assert lookup(31337) is UNKNOWN
    assert UNKNOWN.risk is Risk.INFO
    assert "netstat" in UNKNOWN.advice  # la recommandation explique comment enquêter


def test_table_coherente():
    for port, info in SERVICES.items():
        assert 1 <= port <= 65535
        assert info.name and info.label and info.advice, port
        assert info.name.islower() and " " not in info.name, port
        assert isinstance(info.risk, Risk)


def test_noms_uniques():
    noms = [info.name for info in SERVICES.values()]
    assert len(noms) == len(set(noms))


def test_risques_ordonnes_et_libelles_francais():
    assert Risk.CRITICAL > Risk.HIGH > Risk.MEDIUM > Risk.LOW > Risk.INFO
    assert [r.label for r in Risk] == ["info", "faible", "moyen", "élevé", "critique"]


def test_ports_sensibles_du_top100_sont_documentes():
    # Les services d'administration et de partage du top100 doivent avoir une fiche dédiée
    for port in (21, 22, 23, 135, 139, 445, 1433, 3306, 3389, 5432, 5900):
        assert port in TOP_100 and port in SERVICES, port


def test_resultat_expose_son_service():
    [cible] = parse_targets(["127.0.0.1"])
    assert ScanResult(cible, 445, PortState.OPEN).service.name == "smb"
