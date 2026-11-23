# Imagem oficial multi-arquitetura python:3.12-slim fixada por digest imutável
FROM python:3.15-slim@sha256:65a65fc7b30b06cb6df4930fd4650697cb23f4c2698ab81fc87e4b031bc36928

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
    monitor.py \
    manage.py \
    config.json \
    jogadores_br_steam.json \
    ./
COPY --chown=10001:10001 assets ./assets

USER 10001:10001

CMD ["python3", "-u", "monitor.py"]
