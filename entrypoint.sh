#!/bin/sh
set -e

if [ -z "$ADMIN_PASSWORD" ]; then
    echo "⚠️  ADMIN_PASSWORD не задан — используется значение по умолчанию 'changeme'. Установите свой пароль через переменную окружения ADMIN_PASSWORD!"
fi

exec uvicorn app.main:app --host 0.0.0.0 --port "${PANEL_PORT:-8000}"
