#!/usr/bin/env bash
set -euo pipefail
umask 077
cd "$(dirname "$0")"

echo "=============================================================="
echo "  CoH3 Brasil Monitor — Modo Seguro (Segredo Isolado)"
echo "=============================================================="
echo

if ! python3 -c "import sys; from manage import load_config; from discord_notifier import validate_discord_webhook_url; sys.exit(0 if validate_discord_webhook_url(load_config().get('discord_webhook_url','')) else 1)"; then
  echo "[1/2] Configurando o Webhook de forma isolada em .env.secret (chmod 0600, fora do Git)..."
  python3 manage.py set-webhook --test
  echo
fi

echo "[2/2] Iniciando monitoramento em tempo real (Ctrl+C para encerrar)..."
exec python3 monitor.py
