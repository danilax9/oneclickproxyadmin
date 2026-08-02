#!/bin/sh
# Обход бага docker-compose v1 + новый Docker (KeyError: ContainerConfig)
set -e

cd "$(dirname "$0")"

NAME=proxy-panel
IMAGE=proxy-panel:latest

echo "→ Останавливаем старый контейнер..."
docker stop "$NAME" 2>/dev/null || true
docker rm -f "$NAME" 2>/dev/null || true

echo "→ Собираем образ..."
docker build -t "$IMAGE" .

# Опциональный volume с сертификатами Xray (раскомментируйте при необходимости)
XRAY_MOUNT=""
# XRAY_MOUNT="-v /etc/xray:/etc/xray:ro"

# Важно: не передаём -e ADMIN_PASSWORD поверх --env-file — иначе .env игнорируется
# и подставляется changeme из пустой переменной оболочки.
ENV_ARGS=""
if [ -f .env ]; then
  ENV_ARGS="--env-file .env"
else
  echo "⚠️  Файл .env не найден — используется ADMIN_PASSWORD=${ADMIN_PASSWORD:-changeme}"
  ENV_ARGS="-e ADMIN_PASSWORD=${ADMIN_PASSWORD:-changeme} -e PANEL_PORT=${PANEL_PORT:-8000}"
fi

echo "→ Запускаем контейнер..."
# shellcheck disable=SC2086
docker run -d \
  --name "$NAME" \
  --restart unless-stopped \
  --network host \
  $ENV_ARGS \
  -v proxy-data:/app/data \
  -v proxy-logs:/var/log/3proxy \
  $XRAY_MOUNT \
  "$IMAGE"

echo "→ Готово."
docker ps --filter "name=$NAME"
PANEL_PORT_VAL=$(docker exec "$NAME" printenv PANEL_PORT 2>/dev/null || echo "8000")
echo ""
echo "Панель: http://$(hostname -I 2>/dev/null | awk '{print $1}'):${PANEL_PORT_VAL}"
