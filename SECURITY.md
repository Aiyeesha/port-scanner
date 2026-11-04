# Politique de sécurité

## Versions prises en charge

| Version | Prise en charge |
|---------|-----------------|
| 1.x     | ✅ |
| < 1.0   | ❌ |

## Signaler une vulnérabilité

Merci de **ne pas ouvrir d'issue publique** pour une faille de sécurité.

Utilisez le signalement privé de GitHub :
onglet **Security** du dépôt → **Report a vulnerability**.

Indiquez si possible :
- la version concernée (`port-scanner --version`) ;
- une description du problème et de son impact ;
- les étapes permettant de le reproduire.

⚠️ **N'incluez jamais d'adresse IP publique réelle, de nom d'hôte interne ni de résultat de scan
d'un réseau tiers** dans un signalement : utilisez des adresses de documentation
(`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24` — RFC 5737).

## Délais

Projet personnel maintenu sur le temps libre : accusé de réception visé sous 7 jours.

## Périmètre

Sont notamment concernés :
- tout contournement du garde-fou qui limite par défaut les cibles aux réseaux privés et à la boucle locale ;
- toute consommation de ressources non bornée (nombre de connexions simultanées, mémoire) ;
- tout traitement dangereux des données reçues lors de la lecture des bannières ;
- toute fuite d'information dans les fichiers de sortie au-delà de ce qui a été demandé.

## Usage responsable

Cet outil est destiné à l'apprentissage et à l'audit de **vos propres systèmes**.
Scanner un système sans autorisation peut être illégal (voir la section « Cadre légal » du README).
