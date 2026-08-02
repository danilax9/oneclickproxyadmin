# ---------------------------------------------------------------------------
# Stage 1: сборка 3proxy из исходников
# ---------------------------------------------------------------------------
FROM debian:bookworm-slim AS proxy-build

RUN apt-get update && apt-get install -y --no-install-recommends \
        git build-essential ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build
RUN git clone --depth 1 --branch 0.9.5 https://github.com/3proxy/3proxy.git . \
    && make -f Makefile.Linux \
    && install -m 755 bin/3proxy /usr/local/bin/3proxy

# ---------------------------------------------------------------------------
# Stage 2: финальный образ на базе Python
# ---------------------------------------------------------------------------
FROM python:3.12-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates curl openssl socat cron \
    && curl -fsSL "https://caddyserver.com/api/download?os=linux&arch=amd64" -o /usr/local/bin/caddy \
    && chmod +x /usr/local/bin/caddy \
    && curl -fsSL https://get.acme.sh | sh -s "email=admin@localhost" \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /var/log/3proxy /app/data/caddy /app/data/certs

COPY --from=proxy-build /usr/local/bin/3proxy /usr/local/bin/3proxy

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app ./app
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

ENV PYTHONUNBUFFERED=1 \
    PROXY_CONFIG_PATH=/app/data/3proxy.cfg \
    PROXY_LOG_DIR=/var/log/3proxy \
    THREEPROXY_BIN=/usr/local/bin/3proxy \
    CADDY_BIN=/usr/local/bin/caddy \
    CADDY_DATA=/app/data/caddy \
    CADDYFILE_PATH=/app/data/Caddyfile \
    CERTS_DIR=/app/data/certs \
    ACME_SH=/root/.acme.sh/acme.sh \
    PANEL_PORT=8000

EXPOSE 8000

VOLUME ["/app/data"]

ENTRYPOINT ["/entrypoint.sh"]
