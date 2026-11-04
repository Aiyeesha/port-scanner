# Journal des modifications

Format inspiré de [Keep a Changelog](https://keepachangelog.com/fr/1.1.0/),
versionnage [sémantique](https://semver.org/lang/fr/).

## [Non publié]

## [1.1.0] — 2026-11-04

### Ajouté
- Interface web locale : commande `port-scanner-web` (module `webui`, fichiers `web/` embarqués dans
  le paquet), bilingue français/anglais, thèmes clair et sombre, export JSON.
- Défenses du serveur local : écoute sur la boucle locale uniquement, jeton aléatoire de 256 bits
  transmis dans le fragment de l'URL puis dans l'en-tête `X-Scan-Token` (comparaison à temps
  constant), contrôle des en-têtes `Host` (DNS rebinding) et `Origin` (CSRF), aucune autorisation
  CORS, corps JSON borné à 4 Kio, un seul scan à la fois, CSP stricte sans script en ligne,
  en-têtes `nosniff`, `DENY`, `no-referrer`, `no-store`, réponses d'erreur génériques.
- Le garde-fou « réseaux privés » ne peut pas être levé depuis l'interface web.
- Captures d'écran de l'interface dans `docs/`.
- Volet détection (`detection/`) : guide Wireshark/tshark pas à pas (FR/EN), trois captures de
  laboratoire (scan, trafic normal, client très actif), deux règles Suricata (rafale de SYN, rafale
  de RST) et une règle Sigma de corrélation `value_count` (ports distincts par source), rattachées
  à MITRE ATT&CK T1046.
- CI : job « Détection · Suricata + Sigma » qui rejoue les captures et vérifie les alertes attendues
  (y compris l'absence d'alerte sur le trafic normal) et valide la règle Sigma.

## [1.0.0] — 2026-11-04

Première version stable : ligne de commande et formats JSON/CSV figés.

### Ajouté
- Ossature du projet : paquet `port_scanner` (disposition `src/`), commande `port-scanner`
  (options `--help` et `--version`), tests de fumée et de ligne de commande.
- Intégration continue GitHub Actions (Python 3.11 et 3.14, Ubuntu et Windows) et Dependabot.
- Politique de sécurité, licence MIT, README bilingue avec cadre légal.
- Module `ports` : analyse des listes de ports (`22`, `20-25`, `22,80,443`) et préréglages
  `top100`, `well-known`, `all` ; validation stricte (chiffres ASCII uniquement, bornes 1–65535,
  plages inversées et éléments vides refusés).
- Module `targets` : analyse des cibles (IP, réseau CIDR, nom d'hôte) avec dédoublonnage
  et plafond du nombre d'adresses (1024 par défaut, contrôlé avant toute énumération).
- Garde-fou « sécurisé par défaut » : seuls les réseaux privés (RFC 1918, IPv6 ULA) et la boucle
  locale sont autorisés sans option explicite ; multicast, adresses non spécifiées et réservées
  toujours refusées ; contrôle de chaque adresse résolue par DNS et des adresses IPv6 mappées ;
  formes d'IP abrégées ambiguës (`127.1`, `0x7f.1`) refusées.
- Module `scanner` : scan TCP « connect » asynchrone (asyncio) avec trois états (ouvert, fermé,
  filtré), mesure de latence, fermeture systématique des connexions ouvertes.
- Pool de travailleurs à concurrence bornée (100 par défaut, 500 maximum) et génération
  paresseuse des tentatives ; délai par tentative borné (30 s maximum) ; scan limité à
  262 144 tentatives, refusé avant toute connexion au-delà.
- Reconnaissance du refus de connexion sur tous les systèmes (POSIX et codes Windows 10061/1225).
- Module `services` : fiches de ~50 services TCP (nom, description, niveau de risque de « info »
  à « critique », recommandation de défense) ; propriété `ScanResult.service`.
- Module `banner` : lecture passive et optionnelle des bannières (`grab_banners`), bornée en taille
  (1 Kio) et en durée (2 s par défaut, 10 s maximum) ; neutralisation de tout caractère non
  imprimable (séquences d'échappement de terminal, contrôles C0/C1, caractères Unicode invisibles
  ou bidirectionnels) ; troncature à 200 caractères.
- Ligne de commande complète : options de scan (`-p`, `-t`, `-c`, `--max-hosts`, `--banners`,
  `--banner-timeout`, `--allow-public`) et de sortie (`-f text|json|csv`, `-o`, `--force`, `--all`,
  `--fail-on`, `--no-color`, `-q`) ; progression sur la sortie d'erreur.
- Module `report` : tableau lisible avec recommandations triées par risque ; JSON et CSV aux clés
  anglaises stables ; neutralisation de l'injection de formules dans le CSV (OWASP).
- Codes de sortie : 0 succès, 1 seuil `--fail-on` atteint, 2 erreur de saisie, 3 erreur d'exécution,
  130 interruption.
- Fichier de sortie jamais écrasé sans `--force` (vérifié avant le scan) ; sortie redirigée en UTF-8
  sous Windows.
- Qualité : analyse statique Ruff (style, logique et règles de sécurité Bandit) et vérification du
  formatage en CI ; tests exécutés en mode développement de Python avec tout avertissement traité
  comme une erreur (détection des sockets non refermés).
- Documentation complète en français et en anglais (installation, options, formats, fonctionnement,
  conception sécurisée, limites).

[Non publié]: https://github.com/Aiyeesha/port-scanner/compare/v1.0.0...HEAD
[1.0.0]: https://github.com/Aiyeesha/port-scanner/releases/tag/v1.0.0
