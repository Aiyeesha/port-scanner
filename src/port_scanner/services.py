"""
Identification des services et niveau de risque.

Associe un numéro de port au service qui l'utilise HABITUELLEMENT, avec un niveau
de risque et une recommandation de défense (point de vue Blue Team).

⚠️ Limite importante : un port n'est qu'une CONVENTION. Rien n'empêche un service
d'écouter ailleurs (SSH sur 2222, une porte dérobée sur 443…). Le nom affiché est
donc une hypothèse ; la bannière (option --banners) aide à la confirmer.

Les niveaux de risque décrivent un service EXPOSÉ au-delà du réseau qui en a besoin
(typiquement sur Internet). Ils relèvent d'une appréciation pédagogique : il n'existe
pas de référentiel officiel qui note un port (CVSS note des vulnérabilités, pas des ports).
"""

from __future__ import annotations

import enum
from dataclasses import dataclass


class Risk(enum.IntEnum):
    """Niveau de risque ; IntEnum permet de trier et comparer (Risk.HIGH > Risk.LOW)."""

    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @property
    def label(self) -> str:
        """Libellé français affiché à l'utilisateur."""
        return {0: "info", 1: "faible", 2: "moyen", 3: "élevé", 4: "critique"}[self.value]


@dataclass(frozen=True)
class ServiceInfo:
    """Description d'un service attendu sur un port."""

    name: str  # nom court, ex. « ssh »
    label: str  # description lisible
    risk: Risk
    advice: str  # recommandation de défense


def _s(name: str, label: str, risk: Risk, advice: str) -> ServiceInfo:
    """Raccourci de construction, pour garder la table lisible."""
    return ServiceInfo(name, label, risk, advice)


# ─────────────────────────────────────────────────────────────
# Table des services connus (TCP)
# ─────────────────────────────────────────────────────────────
SERVICES: dict[int, ServiceInfo] = {
    # ── Protocoles en clair : identifiants lisibles sur le réseau ──
    21: _s(
        "ftp",
        "Transfert de fichiers FTP",
        Risk.HIGH,
        "Identifiants et données circulent en clair : remplacer par SFTP ou FTPS.",
    ),
    23: _s(
        "telnet",
        "Accès distant Telnet",
        Risk.CRITICAL,
        "Protocole en clair et sans chiffrement : désactiver et utiliser SSH.",
    ),
    110: _s("pop3", "Messagerie POP3", Risk.HIGH, "Authentification en clair : imposer POP3S (port 995)."),
    143: _s("imap", "Messagerie IMAP", Risk.HIGH, "Authentification en clair : imposer IMAPS (port 993)."),
    # ── Accès distant ──
    22: _s(
        "ssh",
        "Accès distant SSH",
        Risk.MEDIUM,
        "Authentification par clé uniquement, connexion root interdite, accès restreint par IP "
        "et protection contre la force brute (fail2ban, limitation de débit).",
    ),
    3389: _s(
        "rdp",
        "Bureau à distance Windows (RDP)",
        Risk.CRITICAL,
        "Ne jamais exposer sur Internet : passer par un VPN ou une passerelle RD, "
        "activer NLA et l'authentification multifacteur.",
    ),
    5900: _s(
        "vnc",
        "Prise de contrôle à distance VNC",
        Risk.HIGH,
        "Souvent faiblement authentifié et non chiffré : limiter au réseau local ou tunneliser via SSH/VPN.",
    ),
    5985: _s(
        "winrm",
        "Administration Windows à distance (WinRM, HTTP)",
        Risk.HIGH,
        "Réserver aux postes d'administration ; préférer WinRM sur HTTPS (5986).",
    ),
    5986: _s(
        "winrm-https",
        "Administration Windows à distance (WinRM, HTTPS)",
        Risk.MEDIUM,
        "Réserver aux postes d'administration et journaliser les sessions.",
    ),
    1723: _s(
        "pptp",
        "VPN PPTP",
        Risk.HIGH,
        "Chiffrement PPTP considéré comme cassé : migrer vers WireGuard, IPsec ou OpenVPN.",
    ),
    10000: _s(
        "webmin",
        "Console d'administration web (souvent Webmin)",
        Risk.HIGH,
        "Interface d'administration : ne jamais l'exposer, la placer derrière un VPN.",
    ),
    # ── Réseau Windows / annuaire ──
    135: _s(
        "msrpc",
        "Appel de procédure distante Windows (RPC)",
        Risk.HIGH,
        "Indispensable sur un réseau Windows mais à bloquer en périphérie : jamais exposé sur Internet.",
    ),
    139: _s(
        "netbios-ssn",
        "Session NetBIOS",
        Risk.HIGH,
        "Désactiver NetBIOS sur TCP/IP s'il n'est pas utilisé ; bloquer en périphérie.",
    ),
    445: _s(
        "smb",
        "Partage de fichiers Windows (SMB)",
        Risk.CRITICAL,
        "Vecteur historique de vers et rançongiciels (WannaCry/EternalBlue) : jamais exposé sur Internet, "
        "SMBv1 désactivé, signature SMB activée.",
    ),
    88: _s(
        "kerberos",
        "Authentification Kerberos (contrôleur de domaine)",
        Risk.MEDIUM,
        "Signale un contrôleur de domaine : ne doit être joignable que depuis le réseau interne.",
    ),
    389: _s(
        "ldap",
        "Annuaire LDAP",
        Risk.HIGH,
        "Exiger la signature LDAP et la liaison de canal, préférer LDAPS (636) ; jamais exposé.",
    ),
    636: _s(
        "ldaps",
        "Annuaire LDAP sur TLS",
        Risk.MEDIUM,
        "Réserver au réseau interne ; vérifier la validité du certificat.",
    ),
    # ── Web ──
    80: _s(
        "http",
        "Web HTTP",
        Risk.LOW,
        "Rediriger vers HTTPS et activer HSTS ; vérifier qu'aucune page d'administration n'est servie.",
    ),
    443: _s("https", "Web HTTPS", Risk.LOW, "Imposer TLS 1.2 minimum et maintenir le serveur à jour."),
    8000: _s(
        "http-alt",
        "Web alternatif (souvent serveur de développement)",
        Risk.MEDIUM,
        "Un serveur de développement ne doit jamais rester exposé.",
    ),
    8080: _s(
        "http-proxy",
        "Web alternatif / proxy / console applicative",
        Risk.MEDIUM,
        "Héberge souvent des consoles d'administration (Tomcat, Jenkins…) : restreindre l'accès.",
    ),
    8443: _s(
        "https-alt",
        "Web HTTPS alternatif",
        Risk.LOW,
        "Vérifier qu'il ne s'agit pas d'une console d'administration exposée.",
    ),
    3128: _s(
        "squid",
        "Proxy HTTP",
        Risk.MEDIUM,
        "Un proxy ouvert permet d'anonymiser des attaques : restreindre aux clients autorisés.",
    ),
    # ── Messagerie ──
    25: _s(
        "smtp",
        "Envoi de courrier SMTP",
        Risk.MEDIUM,
        "Vérifier qu'il ne s'agit pas d'un relais ouvert ; activer STARTTLS.",
    ),
    465: _s("smtps", "SMTP sur TLS", Risk.LOW, "Imposer l'authentification et TLS à jour."),
    587: _s("submission", "Soumission de courrier", Risk.LOW, "Imposer l'authentification et STARTTLS."),
    993: _s("imaps", "IMAP sur TLS", Risk.LOW, "Maintenir TLS à jour ; protéger contre la force brute."),
    995: _s("pop3s", "POP3 sur TLS", Risk.LOW, "Maintenir TLS à jour ; protéger contre la force brute."),
    # ── Infrastructure ──
    53: _s(
        "dns",
        "DNS (TCP : transferts de zone et grosses réponses)",
        Risk.MEDIUM,
        "Interdire les transferts de zone (AXFR) aux hôtes non autorisés et la récursion ouverte.",
    ),
    111: _s(
        "rpcbind",
        "Annuaire RPC Unix (rpcbind)",
        Risk.HIGH,
        "Révèle les services RPC (dont NFS) : bloquer en périphérie.",
    ),
    2049: _s(
        "nfs", "Partage de fichiers NFS", Risk.HIGH, "Restreindre les exports par adresse et éviter no_root_squash."
    ),
    873: _s(
        "rsync",
        "Synchronisation rsync",
        Risk.HIGH,
        "Modules souvent accessibles sans mot de passe : exiger une authentification ou passer par SSH.",
    ),
    179: _s("bgp", "Routage BGP", Risk.MEDIUM, "Filtrer strictement aux pairs BGP connus."),
    5060: _s(
        "sip",
        "Téléphonie SIP",
        Risk.MEDIUM,
        "Cible de fraude téléphonique : restreindre et surveiller les tentatives d'enregistrement.",
    ),
    # ── Bases de données et caches : jamais exposés ──
    1433: _s(
        "mssql",
        "Base de données Microsoft SQL Server",
        Risk.HIGH,
        "Une base de données ne doit jamais être exposée : accès réservé aux serveurs applicatifs.",
    ),
    1521: _s(
        "oracle",
        "Base de données Oracle",
        Risk.HIGH,
        "Une base de données ne doit jamais être exposée : accès réservé aux serveurs applicatifs.",
    ),
    3306: _s(
        "mysql",
        "Base de données MySQL / MariaDB",
        Risk.HIGH,
        "Une base de données ne doit jamais être exposée : accès réservé aux serveurs applicatifs.",
    ),
    5432: _s(
        "postgresql",
        "Base de données PostgreSQL",
        Risk.HIGH,
        "Une base de données ne doit jamais être exposée : accès réservé aux serveurs applicatifs.",
    ),
    6379: _s(
        "redis",
        "Cache Redis",
        Risk.CRITICAL,
        "Souvent sans authentification : lier à 127.0.0.1, activer l'authentification (ACL) et le mode protégé.",
    ),
    9200: _s(
        "elasticsearch",
        "Moteur de recherche Elasticsearch (API REST)",
        Risk.CRITICAL,
        "Cause fréquente de fuites massives de données : activer la sécurité et ne jamais l'exposer.",
    ),
    11211: _s("memcached", "Cache Memcached", Risk.HIGH, "Aucune authentification par défaut : lier à 127.0.0.1."),
    27017: _s(
        "mongodb",
        "Base de données MongoDB",
        Risk.CRITICAL,
        "Activer l'authentification et lier aux seules interfaces nécessaires.",
    ),
    2375: _s(
        "docker",
        "API Docker non chiffrée",
        Risk.CRITICAL,
        "Équivaut à un accès root sur l'hôte : ne jamais exposer, utiliser TLS (2376) ou le socket local.",
    ),
    # ── Périphériques ──
    631: _s("ipp", "Impression IPP (CUPS)", Risk.MEDIUM, "Limiter au réseau local et maintenir CUPS à jour."),
    9100: _s(
        "jetdirect",
        "Impression directe (JetDirect)",
        Risk.MEDIUM,
        "Permet d'envoyer des tâches sans authentification : limiter au réseau local.",
    ),
    554: _s(
        "rtsp",
        "Flux vidéo RTSP (caméras)",
        Risk.MEDIUM,
        "Caméras souvent livrées avec mots de passe par défaut : les changer et isoler le réseau.",
    ),
    548: _s("afp", "Partage de fichiers Apple (AFP)", Risk.MEDIUM, "Protocole obsolète : migrer vers SMB3."),
}

# Service renvoyé pour un port absent de la table
UNKNOWN = ServiceInfo(
    "inconnu",
    "Service non répertorié",
    Risk.INFO,
    "Identifier le programme qui écoute (Windows : netstat -ano ; Linux : ss -ltnp) "
    "et fermer le port s'il n'est pas nécessaire.",
)


def lookup(port: int) -> ServiceInfo:
    """Renvoie le service habituellement associé au port (ou UNKNOWN)."""
    return SERVICES.get(port, UNKNOWN)
