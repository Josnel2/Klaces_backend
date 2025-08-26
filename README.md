# Klaces_backend

Backend Django pour la gestion des utilisateurs et des fonctionnalités de l'application Klaces.

## Prérequis
- Python 3.10+
- pip
- Git

## Installation

1. Cloner le dépôt :
   ```powershell
   git clone <url-du-repo>
   cd Klaces_backend
   ```
2. Créer et activer un environnement virtuel :
   ```powershell
   python -m venv env
   .\env\Scripts\Activate.ps1
   ```
3. Installer les dépendances :
   ```powershell
   pip install django
   ```

## Démarrage du projet

1. Appliquer les migrations :
   ```powershell
   python manage.py migrate
   ```
2. Lancer le serveur de développement :
   ```powershell
   python manage.py runserver
   ```

## Gestion des branches Git
- `main` : version stable
- `develop` : développement général
- `feature/nom` : nouvelle fonctionnalité
- `bugfix/nom` : correction de bug
- `hotfix/nom` : correction urgente
- `release/nom` : préparation d'une version

## Auteur
- Josnel2

## Licence
Ce projet est sous licence MIT.