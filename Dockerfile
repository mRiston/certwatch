FROM python:3.12.12-slim-bookworm

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    CERTWATCH_DB_PATH=/data/certwatch.db \
    CERTWATCH_CONFIG_FILE=/app/config/endpoints.yaml

WORKDIR /app

RUN groupadd --gid 10001 certwatch \
    && useradd --uid 10001 --gid certwatch --home-dir /home/certwatch --create-home --shell /usr/sbin/nologin certwatch \
    && mkdir -p /data /app/config \
    && chown -R certwatch:certwatch /data /home/certwatch

COPY requirements.txt ./
RUN pip install --no-cache-dir --requirement requirements.txt

COPY --chown=certwatch:certwatch app ./app
COPY --chown=certwatch:certwatch config ./config

USER 10001:10001
EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
  CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8080/health', timeout=3)"]

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8080", "--no-access-log"]
