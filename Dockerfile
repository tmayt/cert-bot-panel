FROM python:3.12-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    certbot \
    openssl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app/ ./app/
COPY hooks/ ./hooks/
RUN chmod +x hooks/*.py

RUN mkdir -p /data/letsencrypt /data/db /data/state

ENV CERTBOT_CONFIG_DIR=/data/letsencrypt
ENV CERTBOT_WORK_DIR=/data/letsencrypt/work
ENV CERTBOT_LOGS_DIR=/data/letsencrypt/logs
ENV DATABASE_PATH=/data/db/certbot.db
ENV STATE_DIR=/data/state

EXPOSE 8000

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
