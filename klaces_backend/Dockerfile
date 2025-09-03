FROM python:3.12-slim-bookworm

WORKDIR /app

#Variables d'environnement

ENV EMAIL_HOST=smtp.gmail.com
ENV EMAIL_HOST_USER=klaces237@gmail.com
ENV EMAIL_HOST_PASSWORD="ljbr paez vugc llrw"
ENV EMAIL_PORT=587
ENV EMAIL_USE_TLS=True

COPY . .

COPY requirements.txt .

RUN pip install --no-cache-dir -r requirements.txt

EXPOSE 8000

CMD ["python", "manage.py", "runserver", "0.0.0.0:8000"]