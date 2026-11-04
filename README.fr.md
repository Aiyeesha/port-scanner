# port-scanner

[![Tests](https://github.com/Aiyeesha/port-scanner/actions/workflows/tests.yml/badge.svg)](https://github.com/Aiyeesha/port-scanner/actions/workflows/tests.yml)
![Python](https://img.shields.io/badge/python-3.11%20%7C%203.14-blue)
![Dépendances](https://img.shields.io/badge/d%C3%A9pendances-aucune-brightgreen)
![Licence](https://img.shields.io/badge/licence-MIT-green)

🇬🇧 [English version](README.md)

Scanner de ports TCP **asynchrone**, **sécurisé par défaut**, qui ne se contente pas de lister les
ports ouverts : il indique le **service** probable, son **niveau de risque** et la **mesure de
défense** à appliquer. Un **volet détection** (Blue Team) montre ensuite comment repérer un tel scan
dans le trafic réseau.

---

## ⚖️ Cadre légal — à lire avant toute utilisation

N'utilisez cet outil **que** sur des machines et réseaux dont vous êtes propriétaire,
ou pour lesquels vous disposez d'une **autorisation écrite** du propriétaire.

En France, l'accès ou le maintien frauduleux dans un système de traitement automatisé de données
est réprimé par l'article 323-1 du Code pénal, et la détention ou la mise à disposition d'outils
conçus pour ces infractions **sans motif légitime** par l'article 323-3-1. Un scan non autorisé
peut, selon le contexte, constituer une étape préparatoire d'une telle infraction et engage dans
tous les cas votre responsabilité vis-à-vis du propriétaire du réseau (et souvent des conditions
d'utilisation de votre fournisseur d'accès ou de cloud).

C'est pourquoi l'outil **refuse par défaut** toute cible qui n'est ni privée, ni la boucle locale.

---

## Fonctionnalités

- **Scan TCP « connect »** asynchrone (asyncio) : des centaines de tentatives simultanées dans un seul thread.
- **Trois états** : ouvert, fermé, filtré — avec la latence de chaque réponse.
- **~50 fiches de services** : nom, niveau de risque (info → critique) et recommandation de défense.
- **Lecture de bannières** optionnelle, passive et nettoyée (aucune injection possible dans le terminal).
- **Sorties** : tableau lisible en couleurs, **JSON** et **CSV** stables pour les scripts et les SIEM.
- **Intégration continue** : `--fail-on high` renvoie le code 1 si un port à risque est ouvert.
- **Garde-fous** : réseaux privés uniquement par défaut, plafonds de taille, de durée et de concurrence.
- **Aucune dépendance** : uniquement la bibliothèque standard de Python.

---

## Installation

Prérequis : **Python 3.11 ou plus récent** et **Git**.

### Windows (PowerShell)

```powershell
# 1. Récupérer le code
git clone https://github.com/Aiyeesha/port-scanner.git
cd port-scanner

# 2. Créer un environnement virtuel isolé, puis l'activer
python -m venv .venv
.\.venv\Scripts\Activate.ps1
# Si PowerShell refuse l'activation : Set-ExecutionPolicy -Scope CurrentUser RemoteSigned

# 3. Installer l'outil
pip install .

# 4. Vérifier
port-scanner --version
```

### Linux / macOS

```bash
git clone https://github.com/Aiyeesha/port-scanner.git
cd port-scanner
python3 -m venv .venv
source .venv/bin/activate
pip install .
port-scanner --version
```

---

## Utilisation

```powershell
# Les 100 ports les plus courants de votre propre machine
port-scanner 127.0.0.1

# Trois ports sur tout un réseau domestique
port-scanner 192.168.1.0/24 -p 22,80,443

# Ports système d'un NAS, avec lecture des bannières
port-scanner nas.local -p well-known --banners

# Résultat JSON enregistré dans un fichier
port-scanner 10.0.0.5 -f json -o scan.json

# Contrôle de conformité : code 1 si un service à risque élevé ou critique est exposé
port-scanner 10.0.0.5 --fail-on high
```

Exemple de sortie (poste Windows) :

```text
127.0.0.1
  PORT      ÉTAT      SERVICE        RISQUE    BANNIÈRE
  135/tcp   ouvert    msrpc          élevé
  445/tcp   ouvert    smb            critique

1 adresse(s) × 100 port(s) en 2.08 s — 2 ouvert(s), 98 fermé(s), 0 filtré(s).

Recommandations
  [critique] smb — Vecteur historique de vers et rançongiciels (WannaCry/EternalBlue) : jamais exposé
             sur Internet, SMBv1 désactivé, signature SMB activée.
  [élevé] msrpc — Indispensable sur un réseau Windows mais à bloquer en périphérie : jamais exposé sur Internet.
```

### Cibles acceptées

| Forme | Exemple | Remarque |
|---|---|---|
| Adresse IPv4 / IPv6 | `192.168.1.10`, `::1` | |
| Réseau CIDR | `192.168.1.0/24` | adresses de réseau et de diffusion exclues |
| Nom d'hôte | `nas.local` | **chaque** adresse résolue passe le garde-fou |

### Ports acceptés

| Forme | Exemple |
|---|---|
| Port seul | `22` |
| Plage | `20-25` |
| Liste | `22,80,443` |
| Préréglage | `top100` (défaut), `well-known` (1–1023), `all` (1–65535) |

### Options

| Option | Défaut | Rôle |
|---|---|---|
| `-p`, `--ports` | `top100` | ports à scanner |
| `-t`, `--timeout` | `1.0` | délai par tentative, en secondes (30 max) |
| `-c`, `--concurrency` | `100` | tentatives simultanées (1 à 500) |
| `--max-hosts` | `1024` | nombre maximal d'adresses (65 536 max) |
| `--banners` | désactivé | lit la bannière des ports ouverts |
| `--banner-timeout` | `2.0` | délai de lecture d'une bannière (10 s max) |
| `--allow-public` | désactivé | autorise les cibles hors réseaux privés (avec autorisation écrite) |
| `-f`, `--format` | `text` | `text`, `json` ou `csv` |
| `-o`, `--output` | écran | fichier de sortie (jamais écrasé sans `--force`) |
| `--all` | désactivé | inclut les ports fermés et filtrés |
| `--fail-on` | désactivé | `info`, `low`, `medium`, `high` ou `critical` |
| `--no-color` | | désactive les couleurs (la variable `NO_COLOR` est aussi respectée) |
| `-q`, `--quiet` | | ni progression ni avertissement |

### Codes de sortie

| Code | Signification |
|---|---|
| `0` | scan terminé (et seuil `--fail-on` non atteint) |
| `1` | au moins un port ouvert atteint le seuil `--fail-on` |
| `2` | erreur de saisie, ou cible refusée par le garde-fou |
| `3` | erreur d'exécution (fichier de sortie impossible à écrire…) |
| `130` | interruption (Ctrl+C) |

### Format JSON

Clés et valeurs en anglais, **stables** depuis la v1.0.0 :

```json
{
  "tool": "port-scanner",
  "version": "1.0.0",
  "started_at": "2026-11-04T20:00:00+00:00",
  "duration_s": 2.08,
  "targets": 1,
  "ports_per_target": 100,
  "settings": { "ports": "top100", "timeout_s": 1.0, "concurrency": 100, "banners": false, "allow_public": false },
  "summary": { "open": 2, "closed": 98, "filtered": 0 },
  "results": [
    { "address": "127.0.0.1", "source": "127.0.0.1", "port": 445, "state": "open",
      "service": "smb", "risk": "critical", "latency_ms": 1.2, "banner": null, "error": null }
  ]
}
```

---

## Fonctionnement

Pour chaque couple (adresse, port), l'outil ouvre une **vraie connexion TCP** (poignée de main
complète SYN → SYN/ACK → ACK), puis la referme aussitôt :

| Observation | État |
|---|---|
| Connexion acceptée | **ouvert** — un service écoute |
| Refus (paquet RST) | **fermé** — la machine répond, rien n'écoute |
| Aucune réponse avant le délai | **filtré** — un pare-feu ignore probablement les paquets |

Ce mode ne demande **aucun droit administrateur** (contrairement au scan « SYN » de Nmap), mais il est
plus **visible** : chaque connexion peut apparaître dans les journaux du service visé — ce que le volet
détection exploite.

> ℹ️ **Particularité de Windows** : sur la boucle locale, Windows réessaie la connexion pendant environ
> 2 secondes après un refus. Avec un délai inférieur (`-t 1`), un port fermé de `127.0.0.1` peut donc
> apparaître « filtré » sous Windows. Utilisez `-t 3` pour scanner votre propre poste.

---

## Conception sécurisée

| Risque | Protection |
|---|---|
| Scanner un réseau tiers par erreur | seuls les réseaux privés (RFC 1918, IPv6 ULA) et la boucle locale sont autorisés par défaut |
| Contourner le garde-fou | IPv6 mappées (`::ffff:8.8.8.8`) ramenées à l'IPv4 ; **toutes** les réponses DNS contrôlées ; formes abrégées (`127.1`, `0x7f.1`) refusées |
| Faute de frappe qui lance un scan géant | plafond de 1024 adresses, vérifié **avant** énumération ; 262 144 tentatives au plus |
| Saturer sa machine ou le réseau | concurrence bornée (500 max), délai borné (30 s max) |
| Socket laissé ouvert | toute connexion refermée dans un `finally` ; tests exécutés en mode développement avec avertissements en erreurs |
| Bannière piégée (séquences de terminal, « Trojan Source ») | tout caractère non imprimable échappé ; taille et durée de lecture bornées |
| Injection de formules dans le CSV | cellules commençant par `= + - @` préfixées d'une apostrophe (OWASP) |
| Écraser un rapport existant | création exclusive du fichier, `--force` obligatoire |
| Chaîne d'approvisionnement | aucune dépendance d'exécution ; Dependabot et analyse Ruff (règles Bandit) en CI |

---

## Limites

- **TCP uniquement** : pas de scan UDP (DNS 53/udp, SNMP 161/udp… ne sont pas couverts).
- **Le service est déduit du numéro de port** : c'est une hypothèse, que la bannière aide à confirmer.
- **Pas de détection du système d'exploitation** ni des versions au-delà de la bannière.
- **Pas d'évasion** (fragmentation, leurres, ralentissement aléatoire) : ce n'est pas l'objectif d'un
  outil pédagogique orienté défense.

---

## Développement

```powershell
pip install -e ".[dev]"        # installation modifiable + pytest + ruff
python -X dev -m pytest -v     # tests (mode développement : ResourceWarning visibles)
ruff check .                   # analyse statique (style, logique, sécurité)
ruff format .                  # formatage
```

Les tests n'accèdent **jamais** au réseau extérieur : les états réels sont testés sur `127.0.0.1` / `::1`,
le reste par simulation.

## Feuille de route

| Étape | Contenu | État |
|---|---|---|
| 1 | Dépôt, structure, intégration continue | ✅ |
| 2 | Analyse des cibles et des ports, garde-fou réseaux privés | ✅ |
| 3 | Scan TCP « connect » asynchrone (asyncio), concurrence bornée | ✅ |
| 4 | Identification des services, niveau de risque, lecture de bannière (optionnelle) | ✅ |
| 5 | Ligne de commande complète, sorties JSON/CSV, codes de retour | ✅ |
| 6 | Tests sur serveurs locaux, documentation, durcissement → **v1.0.0** | ✅ |
| 7 | Volet détection : capture Wireshark, règle Suricata et règle Sigma | ⏳ |
| 8 | Interface web locale (v1.1, optionnelle) | ⏳ |

## Licence

[MIT](LICENSE) © Aïcha Imène Dahoumane
