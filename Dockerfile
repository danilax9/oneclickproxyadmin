# ---------------------------------------------------------------------------
# Stage 1: сборка 3proxy из исходников
# ---------------------------------------------------------------------------
FROM debian:bookworm-slim AS proxy-build

RUN apt-get update && apt-get install -y --no-install-recommends \
        git build-essential ca-certificates libssl-dev patch \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build
COPY patches/3proxy-ssl-fullchain.patch /tmp/3proxy-ssl-fullchain.patch
RUN git clone --depth 1 --branch 0.9.5 https://github.com/3proxy/3proxy.git . \
    && patch -p1 < /tmp/3proxy-ssl-fullchain.patch \
    && sed -i 's/^#LIBS = -lcrypto -lssl -ldl/LIBS = -lcrypto -lssl -ldl/' Makefile.Linux \
    && sed -i 's/^LIBS = -ldl *$/# LIBS = -ldl/' Makefile.Linux \
    && sed -i 's/^PLUGINS = StringsPlugin/PLUGINS = SSLPlugin StringsPlugin/' Makefile.Linux \
    && make -f Makefile.Linux \
    && install -m 755 bin/3proxy /usr/local/bin/3proxy \
    && install -d /usr/local/lib/3proxy \
    && install -m 755 bin/SSLPlugin.ld.so /usr/local/lib/3proxy/

# ---------------------------------------------------------------------------
# Stage 2: финальный образ на базе Python
# ---------------------------------------------------------------------------
FROM python:3.12-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates curl openssl libssl3 socat cron \
    && curl -fsSL "https://caddyserver.com/api/download?os=linux&arch=amd64" -o /usr/local/bin/caddy \
    && chmod +x /usr/local/bin/caddy \
    && curl -fsSL https://get.acme.sh | sh -s "email=admin@localhost" \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /var/log/3proxy /app/data/caddy /app/data/certs

COPY --from=proxy-build /usr/local/bin/3proxy /usr/local/bin/3proxy
COPY --from=proxy-build /usr/local/lib/3proxy/SSLPlugin.ld.so /usr/local/lib/3proxy/SSLPlugin.ld.so

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
    SSL_PLUGIN_PATH=/usr/local/lib/3proxy/SSLPlugin.ld.so \
    CADDY_BIN=/usr/local/bin/caddy \
    CADDY_DATA=/app/data/caddy \
    CADDYFILE_PATH=/app/data/Caddyfile \
    CERTS_DIR=/app/data/certs \
    ACME_SH=/root/.acme.sh/acme.sh \
    PANEL_PORT=8000

EXPOSE 8000

VOLUME ["/app/data"]

ENTRYPOINT ["/entrypoint.sh"]
