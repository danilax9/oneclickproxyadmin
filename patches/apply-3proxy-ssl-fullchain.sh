#!/bin/sh
# 3proxy 0.9.5 SSL plugin: send full certificate chain (fixes curl error 60).
set -e
cd /build

HDR="src/plugins/SSLPlugin/my_ssl.h"
SRC="src/plugins/SSLPlugin/my_ssl.c"
PLG="src/plugins/SSLPlugin/ssl_plugin.c"
FRAG="/tmp/ssl_cli_ctx_from_files.c.frag"

if ! grep -q ssl_cli_ctx_from_files "$HDR"; then
  sed -i '/SSL_CTX \* ssl_cli_ctx(SSL_CONFIG \*config, X509 \*server_cert, EVP_PKEY \*server_key,char\*\* errSSL);/i\
SSL_CTX * ssl_cli_ctx_from_files(SSL_CONFIG *config, const char *cert_file, const char *key_file, char** errSSL);\
' "$HDR"
fi

if ! grep -q ssl_cli_ctx_from_files "$SRC"; then
  awk -v frag="$FRAG" '
    /^SSL_CTX \* ssl_cli_ctx\(SSL_CONFIG/ {
      while ((getline line < frag) > 0) print line
    }
    { print }
  ' "$SRC" > /tmp/my_ssl.c.new
  mv /tmp/my_ssl.c.new "$SRC"
fi

sed -i \
  's/ssl_cli_ctx(sc, sc->server_cert, sc->server_key, \&errSSL)/ssl_cli_ctx_from_files(sc, srvcert, srvkey, \&errSSL)/' \
  "$PLG"

echo "3proxy SSL fullchain patch applied"
