SSL_CTX * ssl_cli_ctx_from_files(SSL_CONFIG *config, const char *cert_file, const char *key_file, char** errSSL){
 SSL_CTX *ctx;

#if OPENSSL_VERSION_NUMBER < 0x10100000L
 ctx = SSL_CTX_new(SSLv23_server_method());
#else
 ctx = SSL_CTX_new(TLS_server_method());
#endif
 if (!ctx) {
 *errSSL = ERR_error_string(ERR_get_error(), errbuf);
 return NULL;
 }

 if (SSL_CTX_use_certificate_chain_file(ctx, cert_file) <= 0) {
 *errSSL = ERR_error_string(ERR_get_error(), errbuf);
 SSL_CTX_free(ctx);
 return NULL;
 }

 if (SSL_CTX_use_PrivateKey_file(ctx, key_file, SSL_FILETYPE_PEM) <= 0) {
 *errSSL = ERR_error_string(ERR_get_error(), errbuf);
 SSL_CTX_free(ctx);
 return NULL;
 }

 if (!SSL_CTX_check_private_key(ctx)) {
 *errSSL = (char *)"Private key does not match the certificate";
 SSL_CTX_free(ctx);
 return NULL;
 }

 if(config->server_min_proto_version)SSL_CTX_set_min_proto_version(ctx, config->server_min_proto_version);
 if(config->server_max_proto_version)SSL_CTX_set_max_proto_version(ctx, config->server_max_proto_version);
 if(config->server_cipher_list)SSL_CTX_set_cipher_list(ctx, config->server_cipher_list);
 if(config->server_ciphersuites)SSL_CTX_set_ciphersuites(ctx, config->server_ciphersuites);
 return ctx;
}

