FROM python:3.12-slim-bookworm

WORKDIR /app

# Copier le fichier .env dans le conteneur
COPY .env .env

# Copier et installer les dépendances
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copier le reste du code
COPY . .

# Exposer le port Django
EXPOSE 8085

# Lancer Django
CMD ["python", "manage.py", "runserver", "0.0.0.0:8085"]
