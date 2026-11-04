# port-scanner

🇬🇧 [English version](README.md)

Scanner de ports TCP **asynchrone**, **sécurisé par défaut** et accompagné d'un **volet
détection** (Blue Team) : on apprend à scanner, puis à repérer un scan dans le trafic réseau.

> 🚧 **Projet en cours de construction** (v0.1.0 — ossature). Le scan n'est pas encore disponible.

## ⚖️ Cadre légal — à lire avant toute utilisation

N'utilisez cet outil **que** sur des machines et réseaux dont vous êtes propriétaire,
ou pour lesquels vous disposez d'une **autorisation écrite** du propriétaire.

En France, l'accès ou le maintien frauduleux dans un système de traitement automatisé de données
est réprimé par l'article 323-1 du Code pénal, et la détention ou la mise à disposition d'outils
conçus pour ces infractions **sans motif légitime** par l'article 323-3-1. Un scan non autorisé
peut, selon le contexte, constituer une étape préparatoire d'une telle infraction et engage dans
tous les cas votre responsabilité vis-à-vis du propriétaire du réseau (et souvent des conditions
d'utilisation de votre fournisseur d'accès ou de cloud).

C'est pourquoi l'outil **refusera par défaut** toute cible qui n'est ni privée (RFC 1918),
ni la boucle locale : une option explicite sera nécessaire pour lever ce garde-fou.

## Feuille de route

| Étape | Contenu | État |
|---|---|---|
| 1 | Dépôt, structure, intégration continue | ✅ |
| 2 | Analyse des cibles et des ports, garde-fou réseaux privés | ✅ |
| 3 | Scan TCP « connect » asynchrone (asyncio), concurrence bornée | ✅ |
| 4 | Identification des services, niveau de risque, lecture de bannière (optionnelle) | ⏳ |
| 5 | Ligne de commande complète, sorties JSON/CSV, codes de retour | ⏳ |
| 6 | Tests sur serveurs locaux, documentation, durcissement → **v1.0.0** | ⏳ |
| 7 | Volet détection : capture Wireshark, règle Suricata et règle Sigma | ⏳ |
| 8 | Interface web locale (v1.1, optionnelle) | ⏳ |

## Développement

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -e ".[dev]"
pytest -v
port-scanner --version
```

## Licence

[MIT](LICENSE) © Aïcha Imène Dahoumane
