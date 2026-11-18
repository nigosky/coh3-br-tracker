@echo off
chcp 65001 >nul
cd /d "%~dp0"

echo ==============================================================
echo   CoH3 Brasil Monitor — Modo Seguro (Segredo Isolado)
echo ==============================================================
echo.

where python >nul 2>nul
if %errorlevel% neq 0 (
    echo [ERRO] Python 3 nao encontrado no PATH.
    pause
    exit /b 1
)

python -c "import sys; from manage import load_config; from discord_notifier import validate_discord_webhook_url; sys.exit(0 if validate_discord_webhook_url(load_config().get('discord_webhook_url','')) else 1)"
if %errorlevel% neq 0 (
    echo [1/2] Configurando o Webhook de forma isolada em .env.secret ^(fora do Git^)...
    python manage.py set-webhook --test
    if %errorlevel% neq 0 (
        pause
        exit /b 1
    )
)

echo [2/2] Iniciando monitoramento em tempo real (Ctrl+C para encerrar)...
python monitor.py
pause
