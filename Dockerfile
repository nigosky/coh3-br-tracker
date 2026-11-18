FROM python:3.12-slim

RUN groupadd --gid 10001 appgroup \
    && useradd --uid 10001 --gid 10001 --create-home --shell /usr/sbin/nologin appuser \
    && mkdir -p /app /app/data \
    && chown -R 10001:10001 /app

WORKDIR /app

COPY --chown=10001:10001 relic_api.py database.py discord_notifier.py monitor.py manage.py config.json ./

USER 10001:10001

CMD ["python3", "-u", "monitor.py"]
