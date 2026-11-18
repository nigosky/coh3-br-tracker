FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates \
        fonts-dejavu-core \
        fonts-liberation \
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
    monitor.py \
    manage.py \
    config.json \
    jogadores_br_steam.json \
    top20_br_por_modo.json \
    ./
COPY --chown=10001:10001 assets ./assets

USER 10001:10001

CMD ["python3", "-u", "monitor.py"]
