"""
Mise en forme des résultats : tableau lisible, JSON et CSV.

Choix de conception :
  - l'affichage humain (texte) est en français ;
  - les formats machine (JSON, CSV) utilisent des clés et valeurs ANGLAISES et
    STABLES (« open », « critical »…) : c'est ce qu'attendent les scripts, les SIEM
    et les outils d'analyse, et ces valeurs ne changeront pas d'une version à l'autre.
"""

from __future__ import annotations

import csv
import io
import json
from collections import Counter
from collections.abc import Sequence
from dataclasses import dataclass, field

from port_scanner import __version__
from port_scanner.scanner import PortState, ScanResult
from port_scanner.services import Risk

# ─────────────────────────────────────────────────────────────
# 1. Métadonnées d'un scan
# ─────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class ScanMeta:
    """Contexte du scan, reproduit dans les sorties pour la traçabilité."""

    started_at: str                 # date et heure ISO 8601 en UTC
    duration_s: float
    targets: int                    # nombre d'adresses scannées
    ports: int                      # nombre de ports par adresse
    settings: dict = field(default_factory=dict)


def _state_key(state: PortState) -> str:
    """Valeur machine stable : open / closed / filtered."""
    return state.name.lower()


def _risk_key(risk: Risk) -> str:
    """Valeur machine stable : info / low / medium / high / critical."""
    return risk.name.lower()


def select(results: Sequence[ScanResult], include_all: bool) -> list[ScanResult]:
    """Par défaut on ne garde que les ports ouverts ; include_all garde tout."""
    return list(results) if include_all else [r for r in results if r.state is PortState.OPEN]


def summary(results: Sequence[ScanResult]) -> dict[str, int]:
    """Comptage par état, toujours calculé sur TOUS les résultats."""
    counts = Counter(_state_key(r.state) for r in results)
    return {key: counts.get(key, 0) for key in ("open", "closed", "filtered")}


def max_open_risk(results: Sequence[ScanResult]) -> Risk | None:
    """Plus haut niveau de risque parmi les ports ouverts (None si aucun port ouvert)."""
    risks = [r.service.risk for r in results if r.state is PortState.OPEN]
    return max(risks) if risks else None


def _row(result: ScanResult) -> dict:
    """Un résultat sous forme de dictionnaire « à plat » (JSON et CSV)."""
    service = result.service
    return {
        "address": str(result.target.address),
        "source": result.target.source,
        "port": result.port,
        "state": _state_key(result.state),
        "service": service.name,
        "risk": _risk_key(service.risk),
        "latency_ms": result.latency_ms,
        "banner": result.banner,
        "error": result.error,
    }


# ─────────────────────────────────────────────────────────────
# 2. JSON
# ─────────────────────────────────────────────────────────────

def to_json(results: Sequence[ScanResult], meta: ScanMeta, include_all: bool = False) -> str:
    """Document JSON complet : outil, contexte, synthèse, puis résultats."""
    document = {
        "tool": "port-scanner",
        "version": __version__,
        "started_at": meta.started_at,
        "duration_s": meta.duration_s,
        "targets": meta.targets,
        "ports_per_target": meta.ports,
        "settings": meta.settings,
        "summary": summary(results),
        "results": [_row(r) for r in select(results, include_all)],
    }
    # ensure_ascii=False : les accents restent lisibles ; le fichier est écrit en UTF-8
    return json.dumps(document, ensure_ascii=False, indent=2)


# ─────────────────────────────────────────────────────────────
# 3. CSV — avec protection contre l'injection de formules
# ─────────────────────────────────────────────────────────────

CSV_FIELDS = ("address", "source", "port", "state", "service", "risk", "latency_ms", "banner", "error")

# Un tableur (Excel, LibreOffice…) interprète comme une FORMULE une cellule qui commence
# par l'un de ces caractères. Une bannière contrôlée par la machine scannée pourrait donc
# contenir « =HYPERLINK(...) » ou pire. Recommandation OWASP « CSV Injection » :
# préfixer ces cellules d'une apostrophe, qui force le tableur à les traiter comme du texte.
_FORMULA_PREFIXES = ("=", "+", "-", "@", "\t", "\r")


def _csv_safe(value: object) -> object:
    """Neutralise une cellule texte qui pourrait être interprétée comme une formule."""
    if isinstance(value, str) and value.startswith(_FORMULA_PREFIXES):
        return "'" + value
    return value


def to_csv(results: Sequence[ScanResult], include_all: bool = False) -> str:
    """Une ligne d'en-tête puis une ligne par résultat."""
    buffer = io.StringIO()
    # lineterminator="\n" : fins de ligne identiques sur tous les systèmes
    writer = csv.DictWriter(buffer, fieldnames=CSV_FIELDS, lineterminator="\n")
    writer.writeheader()
    for result in select(results, include_all):
        writer.writerow({key: _csv_safe(value) for key, value in _row(result).items()})
    return buffer.getvalue()


# ─────────────────────────────────────────────────────────────
# 4. Texte lisible (terminal)
# ─────────────────────────────────────────────────────────────

_RESET = "\033[0m"
_RISK_COLORS = {
    Risk.CRITICAL: "\033[1;91m",   # rouge vif gras
    Risk.HIGH: "\033[91m",         # rouge
    Risk.MEDIUM: "\033[93m",       # jaune
    Risk.LOW: "\033[92m",          # vert
    Risk.INFO: "\033[37m",         # gris
}
_BOLD = "\033[1m"


def _paint(text: str, code: str, enabled: bool) -> str:
    return f"{code}{text}{_RESET}" if enabled else text


def to_text(
    results: Sequence[ScanResult],
    meta: ScanMeta,
    include_all: bool = False,
    color: bool = False,
    advice: bool = True,
) -> str:
    """Tableau par adresse, synthèse et recommandations pour les ports ouverts."""
    lines: list[str] = []
    shown = select(results, include_all)

    # ── Regroupement par adresse, dans l'ordre du scan ──────
    by_host: dict[str, list[ScanResult]] = {}
    for result in shown:
        by_host.setdefault(str(result.target.address), []).append(result)

    for address, host_results in by_host.items():
        source = host_results[0].target.source
        title = address if source == address else f"{address} ({source})"
        lines.append(_paint(title, _BOLD, color))
        lines.append(f"  {'PORT':<10}{'ÉTAT':<10}{'SERVICE':<15}{'RISQUE':<10}BANNIÈRE")
        for r in host_results:
            risk = r.service.risk
            risk_cell = _paint(f"{risk.label:<10}", _RISK_COLORS[risk], color) if r.state is PortState.OPEN else f"{'-':<10}"
            port_cell = f"{r.port}/tcp"
            lines.append(f"  {port_cell:<10}{r.state.value:<10}{r.service.name:<15}{risk_cell}{r.banner or ''}")
        lines.append("")

    if not shown:
        lines.append("Aucun port ouvert trouvé." if not include_all else "Aucun résultat.")
        lines.append("")

    # ── Synthèse (toujours sur l'ensemble des résultats) ────
    counts = summary(results)
    lines.append(
        f"{meta.targets} adresse(s) × {meta.ports} port(s) en {meta.duration_s:.2f} s — "
        f"{counts['open']} ouvert(s), {counts['closed']} fermé(s), {counts['filtered']} filtré(s)."
    )

    # ── Recommandations : une par service ouvert, du plus risqué au moins risqué ──
    if advice:
        services = {r.service for r in results if r.state is PortState.OPEN}
        ordered = sorted(services, key=lambda s: (-s.risk, s.name))
        if ordered:
            lines.append("")
            lines.append(_paint("Recommandations", _BOLD, color))
            for s in ordered:
                lines.append(f"  [{_paint(s.risk.label, _RISK_COLORS[s.risk], color)}] {s.name} — {s.advice}")
    return "\n".join(lines)
