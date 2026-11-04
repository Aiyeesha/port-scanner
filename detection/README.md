# Volet détection — repérer un balayage de ports

🇬🇧 [English version](README.en.md) · ⬅️ [Retour au projet](../README.fr.md)

`port-scanner` apprend à **scanner** ; ce dossier apprend à **détecter un scan**. Le balayage de ports
correspond à la technique MITRE ATT&CK **[T1046 — Network Service Discovery](https://attack.mitre.org/techniques/T1046/)**
(tactique *Discovery*, TA0007) : c'est souvent l'une des premières actions d'un attaquant qui vient de
prendre pied sur un réseau et cherche à se déplacer latéralement.

| Contenu | Rôle |
|---|---|
| [`samples/scan-lab.pcap`](samples/scan-lab.pcap) | capture réelle d'un scan `port-scanner` (101 ports, boucle locale) |
| [`samples/benign.pcap`](samples/benign.pcap) | trafic normal : 20 requêtes web |
| [`samples/busy.pcap`](samples/busy.pcap) | client légitime très actif : 60 requêtes web vers un seul port |
| [`suricata/port-scan.rules`](suricata/port-scan.rules) | deux règles Suricata (IDS réseau) |
| [`sigma/port_scan_distinct_ports.yml`](sigma/port_scan_distinct_ports.yml) | règle Sigma de corrélation (SIEM) |
| [`scripts/check_suricata.sh`](scripts/check_suricata.sh) | rejoue les captures et vérifie les alertes (exécuté en CI) |

Les captures ne contiennent que du trafic de laboratoire sur `127.0.0.1` (services fictifs).

---

## 1. Ce que voit le réseau

Extrait de `scan-lab.pcap` — un port **fermé** (443) puis un port **ouvert** (2222) :

```text
127.0.0.1.55810 > 127.0.0.1.443:   Flags [S]     ← tentative (SYN)
127.0.0.1.443   > 127.0.0.1.55810: Flags [R.]    ← refus (RST+ACK) : port fermé

127.0.0.1.49172 > 127.0.0.1.2222:  Flags [S]     ← tentative
127.0.0.1.2222  > 127.0.0.1.49172: Flags [S.]    ← acceptation (SYN+ACK)
127.0.0.1.49172 > 127.0.0.1.2222:  Flags [.]     ← poignée de main terminée (ACK)
127.0.0.1.2222  > 127.0.0.1.49172: Flags [P.]    ← bannière « SSH-2.0-… » (option --banners)
127.0.0.1.49172 > 127.0.0.1.2222:  Flags [F.]    ← fermeture immédiate par le scanner
```

Sur l'ensemble de la capture : **101 SYN vers 101 ports distincts** en quelques millisecondes,
**99 refus (RST)**, et pour les ports ouverts une connexion complète refermée aussitôt. Trois
indicateurs en découlent :

| Indicateur | Pourquoi c'est suspect | Force |
|---|---|---|
| Rafale de SYN depuis une même source | volume anormal de tentatives | faible : un client actif en produit aussi |
| Rafale de RST renvoyés par une même machine | un client légitime vise des services **ouverts** | forte |
| Nombreux ports de destination **distincts** depuis une même source | c'est la définition même d'un balayage | forte |

---

## 2. Atelier Wireshark (Windows)

### 2.1 Installer Wireshark et Npcap

1. Téléchargez Wireshark sur <https://www.wireshark.org/download.html> (ou `winget install WiresharkFoundation.Wireshark`).
2. Pendant l'installation, acceptez l'installation de **Npcap**.
3. Dans l'installeur de Npcap, **cochez « Support loopback traffic »** : sans cette option, le trafic
   vers `127.0.0.1` est invisible.

### 2.2 Ouvrir la capture fournie (aucun scan nécessaire)

**Fichier → Ouvrir** → `detection/samples/scan-lab.pcap`, puis saisissez ces filtres dans la barre
de filtre d'affichage (en haut) et validez avec Entrée :

| Filtre | Ce qu'il montre | Résultat attendu |
|---|---|---|
| `tcp.flags.syn == 1 && tcp.flags.ack == 0` | les tentatives de connexion | 101 paquets |
| `tcp.flags.reset == 1` | les refus (ports fermés) | 99 paquets |
| `tcp.port == 2222` | la connexion complète vers le faux SSH | 8 paquets, bannière visible |

Puis **Statistiques → Conversations → onglet TCP** : une même adresse source parle à 101 ports
différents, presque toutes les conversations comptent 2 paquets — le profil typique d'un scan.

### 2.3 Capturer votre propre scan

1. Lancez Wireshark et double-cliquez sur **Adapter for loopback traffic capture**.
2. Dans un terminal (environnement virtuel activé) : `port-scanner 127.0.0.1 -t 3`
3. Arrêtez la capture (carré rouge) et appliquez les filtres ci-dessus.

> ⚠️ **À vérifier par vous-même** : sur la boucle locale, Windows réessaie une connexion refusée
> pendant environ 2 secondes (c'est ce qui impose `-t 3`). Vous verrez donc probablement **plusieurs SYN
> par port fermé** dans votre propre capture, contrairement à la capture Linux fournie. Je n'ai pas pu
> le confirmer sur une capture Windows : observez-le et comparez.

### 2.4 En ligne de commande (tshark)

`tshark` est installé avec Wireshark (`C:\Program Files\Wireshark\tshark.exe`, à ajouter au PATH ou à
appeler avec son chemin complet).

```powershell
# Nombre de ports DISTINCTS contactés par chaque source
tshark -r scan-lab.pcap -Y "tcp.flags.syn == 1 && tcp.flags.ack == 0" -T fields -e ip.src -e tcp.dstport |
    Sort-Object -Unique | ForEach-Object { ($_ -split "`t")[0] } | Group-Object | Select-Object Count, Name

# Tableau des conversations TCP
tshark -r scan-lab.pcap -q -z conv,tcp
```

Résultat attendu de la première commande : `101 127.0.0.1`.

---

## 3. Règles Suricata (IDS réseau)

[Suricata](https://suricata.io/) analyse le trafic en temps réel et lève des alertes selon des règles.

| SID | Indicateur | Priorité | Logique |
|---|---|---|---|
| `1000001` | rafale de SYN depuis une même source | 3 (faible) | ≥ 30 SYN en 10 s, une alerte par source et par fenêtre |
| `1000002` | rafale de RST renvoyés par une machine interne | 2 | ≥ 30 RST en 10 s depuis la machine sondée |

Mots-clés utilisés :
- `flow:stateless` : chaque paquet est examiné seul, sans suivi de session ;
- `flags:S,12` : drapeau SYN seul (le `12` ignore les bits ECN CWR/ECE) ; `flags:R+` : RST avec ou sans autres drapeaux ;
- `threshold:type both` : alerte **une seule fois** par fenêtre une fois le seuil atteint (pas d'inondation d'alertes) ;
- SID `1000000–1999999` : plage réservée aux règles locales.

### Validation

Les règles ont été rejouées sur les trois captures (Suricata 7.0.3). La CI refait ce contrôle à chaque modification :

| Capture | Alertes attendues | Interprétation |
|---|---|---|
| `scan-lab.pcap` | 1000001 et 1000002 | le scan est détecté par les deux règles |
| `benign.pcap` | aucune | trafic normal ignoré |
| `busy.pcap` | 1000001 seule | **faux positif connu** de la règle 1 ; la règle 2 reste muette |

C'est pourquoi la règle 1 est classée « indicateur faible » : elle compte des SYN, pas des ports
**distincts**, ce que Suricata ne sait pas faire dans une règle. La corrélation Sigma lève cette limite.

### Tester chez vous (Linux ou WSL)

```bash
sudo apt install suricata
bash detection/scripts/check_suricata.sh
```

### Déployer

1. Copiez `port-scan.rules` dans le dossier de règles et ajoutez-le à `rule-files` dans `suricata.yaml`.
2. Ajustez `HOME_NET` à vos réseaux internes.
3. Excluez vos scanners **autorisés** (scanner de vulnérabilités, supervision) dans `threshold.config` :
   ```text
   suppress gen_id 1, sig_id 1000001, track by_src, ip 10.0.0.50
   suppress gen_id 1, sig_id 1000002, track by_dst, ip 10.0.0.50
   ```
4. Ajustez les seuils (`count`, `seconds`) à votre trafic réel après quelques jours d'observation.

---

## 4. Règle Sigma (SIEM)

[Sigma](https://sigmahq.io/) est un format de règles **indépendant du SIEM** : une même règle se
convertit en requête Splunk, Elastic, Microsoft Sentinel, etc.

Le fichier contient deux documents :
1. une **règle de base** (non alertante) : événement de pare-feu vers une adresse interne (RFC 1918) ;
2. une **corrélation `value_count`** : alerte quand une même `src_ip` atteint **au moins 30 valeurs
   distinctes de `dst_port` en une minute**.

Compter des ports **distincts** élimine le faux positif `busy.pcap` : 60 connexions vers un seul port
ne donnent qu'**une** valeur distincte.

### Validation et conversion

```bash
pip install sigma-cli pysigma-backend-splunk
sigma check detection/sigma/
sigma convert -t splunk --without-pipeline detection/sigma/port_scan_distinct_ports.yml
```

Résultat de la conversion Splunk (vérifié avec sigma-cli 4.0.0) :

```text
dst_ip="10.0.0.0/8" OR dst_ip="172.16.0.0/12" OR dst_ip="192.168.0.0/16"
| bin _time span=1m
| stats dc(dst_port) as value_count by _time src_ip
| search value_count >= 30
```

> ⚠️ **Adaptation nécessaire** : les noms de champs `src_ip`, `dst_ip`, `dst_port` suivent la
> taxonomie Sigma de la catégorie `firewall`. Dans un vrai SIEM, ils doivent être rapprochés de ceux de
> vos journaux (pipeline de conversion) ; sans cela, la requête ne trouvera rien.

---

## 5. Limites de la détection

| Technique d'évitement | Effet | Parade |
|---|---|---|
| Scan **lent** (quelques ports par minute) | passe sous les seuils de 10 s / 1 min | corrélation sur des fenêtres longues (1 h, 24 h) |
| Scan **distribué** (plusieurs sources) | aucune source n'atteint le seuil | regrouper par destination (`group-by: dst_ip`) |
| Liste de ports **courte** et ciblée | peu de SYN, peu de RST | surveiller les accès aux ports sensibles (RDP, SMB) depuis des sources inhabituelles |
| Pare-feu qui **ignore** (DROP) au lieu de refuser | pas de RST : la règle 1000002 ne voit rien | journaux du pare-feu (règle Sigma) |

Aucune règle n'est parfaite : la défense combine **plusieurs indicateurs** et **plusieurs sources**
(IDS réseau, pare-feu, journaux des hôtes).
