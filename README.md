# FideliWallet

**Plateforme SaaS de cartes de fidélité digitales pour commerçants locaux.** Les clients ajoutent leur carte à **Apple Wallet** ou **Google Wallet** en scannant un QR code, et le commerçant tamponne la carte depuis son téléphone. Plus de carte papier à perdre, et le commerçant peut contacter ses clients directement.

Projet personnel, conçu, développé et mis en production en solo par Justin Gailliez.

## Fonctionnalités

**Pour les clients**
- Inscription en scannant un QR code propre au commerçant (page `/{commerçant}/join`)
- Carte ajoutée en un clic à Apple Wallet (`.pkpass`) ou Google Wallet
- Carte mise à jour automatiquement à chaque tampon, avec notification push

**Pour les commerçants** (espace `/{commerçant}/admin`)
- Tableau de bord avec statistiques d'activité de leurs clients
- Ajout de tampons par scan du QR code du client ou depuis l'espace admin
- Historique des tampons, gestion des clients, paramètres de la récompense
- Envoi d'emails et de notifications push à un groupe de clients (clients actifs, inactifs, jamais venus...)
- Abonnement mensuel géré via Stripe

**Pour l'administrateur** (`/super-admin/dashboard`)
- Création et suppression de commerçants, suivi des abonnements
- Formulaire de contact et page de présentation du produit

## Architecture

| Élément | Technologie |
|---|---|
| Serveur | Node.js, Express 5 |
| Base de données | SQLite (`better-sqlite3`), sauvegarde quotidienne automatique (`node-cron`) |
| Apple Wallet | `passkit-generator` (génération des `.pkpass`) et service web PassKit (`/v1/devices/...`) |
| Notifications push Apple | `apn` (APNs) |
| Google Wallet | API Google Wallet Objects (`google-auth-library`) |
| Paiement | Stripe (abonnements et webhooks) |
| Emails | Resend |
| Sécurité | mots de passe hachés avec `bcrypt`, authentification HTTP Basic pour le super-admin |
| QR codes et images | `qrcode`, `sharp` |

Tout le serveur est dans `server.js`. `init-database.js` crée le schéma (commerçants, clients, cartes, enregistrements d'appareils, historiques) avec quelques données de démonstration. `templates/default.pass/` est le modèle de carte Apple Wallet.

## Installation

Prérequis : Node.js 20 ou plus. Pour tester l'ajout de cartes aux Wallets, il faut aussi un compte développeur Apple et un compte Google Wallet.

```bash
git clone https://github.com/Justglz/FideliWallet.git
cd FideliWallet
npm install
cp .env.example .env     # puis remplir les valeurs
npm run init-db          # crée fideli.db avec des données de démonstration
npm start
```

Variables d'environnement : voir [`.env.example`](.env.example). `AUTH_TOKEN` et `SUPER_ADMIN_PASS` sont obligatoires, le serveur refuse de démarrer sans elles.

**Fichiers à fournir vous-même** (jamais publiés, voir `.gitignore`) : `wwdr.pem`, `certificate.pem`, `key.pem` (certificat Apple Pass Type ID), `apns_signer.p12` (notifications push) et le fichier JSON du compte de service Google.

## Remarques

- Le code publié est une version anonymisée du code de production : identifiants, domaine, clés et données clients ont été retirés.
- Le dépôt n'inclut pas de tests automatisés. Les dépendances ont été remises à jour pour la publication et le projet n'a pas été retesté de bout en bout depuis ce dépôt.
- Le compte de démonstration créé par `init-database.js` (commerçant `barber-001`) n'est là que pour essayer l'application en local.

## Auteur

Justin Gailliez, étudiant en ingénierie financière à l'ESILV.
