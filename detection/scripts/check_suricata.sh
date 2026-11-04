#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────
# Vérifie les règles Suricata en rejouant les captures d'exemple.
# Utilisé par la CI ; utilisable sous Linux ou WSL :
#     bash detection/scripts/check_suricata.sh
# Prérequis : suricata (sudo apt install suricata)
# ─────────────────────────────────────────────────────────────
set -euo pipefail                         # arrêt à la première erreur

ROOT="$(cd "$(dirname "$0")/.." && pwd)"  # dossier detection/
RULES="$ROOT/suricata/port-scan.rules"
WORK="$(mktemp -d)"                       # dossier temporaire, supprimé à la fin
trap 'rm -rf "$WORK"' EXIT

# Rejoue une capture et renvoie la liste des SID déclenchés (un par ligne)
replay() {
  local name="$1" out="$WORK/$1"
  mkdir -p "$out"
  # -k none : ignore les sommes de contrôle (les captures sur la boucle locale en ont souvent d'invalides)
  # HOME_NET : le laboratoire se déroule sur 127.0.0.0/8
  suricata -r "$ROOT/samples/$name.pcap" -S "$RULES" -k none -l "$out" \
    --set vars.address-groups.HOME_NET="[127.0.0.0/8]" >/dev/null 2>&1
  grep -o '\[1:[0-9]*:' "$out/fast.log" | cut -d: -f2 | sort -u || true
}

fail=0
expect() {   # expect <capture> <SID attendus, séparés par des espaces ou vide>
  local got want
  got="$(replay "$1" | tr '\n' ' ' | sed 's/ $//')"
  want="$2"
  if [[ "$got" == "$want" ]]; then
    echo "OK    $1 : [${got:-aucune alerte}]"
  else
    echo "ÉCHEC $1 : attendu [${want:-aucune alerte}], obtenu [${got:-aucune alerte}]"
    fail=1
  fi
}

suricata -T -S "$RULES" -l "$WORK" --set vars.address-groups.HOME_NET="[127.0.0.0/8]" >/dev/null
echo "OK    syntaxe des règles"
expect scan-lab "1000001 1000002"   # le scan déclenche les deux règles
expect benign   ""                  # trafic normal : aucune alerte
expect busy     "1000001"           # client très actif : faux positif connu de la règle 1 seulement
exit "$fail"
