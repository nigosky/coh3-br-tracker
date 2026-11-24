# Imagem oficial multi-arquitetura python:3.12-slim fixada por digest imutável
FROM python:3.12-slim@sha256:5e2bdb1b0d542d5039cffb8181c65930093949194a65c365dfb1b0fe13a4fa5b

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates \
        fonts-dejavu-core \
        fonts-liberation \
        fonts-roboto \
        fonts-noto-cjk \
        python3-pil \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --gid 10001 appgroup \
    && useradd --uid 10001 --gid 10001 --create-home --shell /usr/sbin/nologin appuser \
    && mkdir -p /app /app/data \
    && chown -R 10001:10001 /app

WORKDIR /app

COPY --chown=10001:10001 \
    security.py \
    card_renderer.py \
    relic_api.py \
    database.py \
    discord_notifier.py \
    smurf_alert.py \
    watchlist_monitor.py \
    monitor.py \
    manage.py \
    config.json \
    jogadores_br_steam.json \
    ./
COPY --chown=10001:10001 assets ./assets

USER 10001:10001

CMD ["python3", "-u", "monitor.py"]
