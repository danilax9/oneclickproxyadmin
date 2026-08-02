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

ENV_FILE=""
if [ -f .env ]; then
  ENV_FILE="--env-file .env"
fi

echo "→ Запускаем контейнер..."
docker run -d \
  --name "$NAME" \
  --restart unless-stopped \
  --network host \
  $ENV_FILE \
  -e ADMIN_PASSWORD="${ADMIN_PASSWORD:-changeme}" \
  -e PANEL_PORT="${PANEL_PORT:-8000}" \
  -v proxy-data:/app/data \
  -v proxy-logs:/var/log/3proxy \
  $XRAY_MOUNT \
  "$IMAGE"

echo "→ Готово."
docker ps --filter "name=$NAME"
echo ""
echo "Панель: http://$(hostname -I 2>/dev/null | awk '{print $1}'):${PANEL_PORT:-8000}"
