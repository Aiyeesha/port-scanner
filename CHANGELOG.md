# Journal des modifications

Format inspiré de [Keep a Changelog](https://keepachangelog.com/fr/1.1.0/),
versionnage [sémantique](https://semver.org/lang/fr/).

## [Non publié]

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
