static ptls_key_exchange_algorithm_t *net_quic_picotls_key_exchanges[] = {
#if PTLS_OPENSSL_HAVE_X25519
    &ptls_openssl_x25519,
#endif
    &ptls_openssl_secp256r1,
    &ptls_openssl_secp384r1,
    &ptls_openssl_secp521r1,
#if PTLS_OPENSSL_HAVE_X25519MLKEM768
    &ptls_openssl_x25519mlkem768,
#endif
    NULL,
};

static ptls_cipher_suite_t *net_quic_picotls_cipher_suites[] = {
    &ptls_openssl_aes128gcmsha256,
    &ptls_openssl_aes256gcmsha384,
#if PTLS_OPENSSL_HAVE_CHACHA20_POLY1305
    &ptls_openssl_chacha20poly1305sha256,
#endif
    NULL,
};

static void
net_quic_tls_context_defaults(net_quic_connection *ep)
{
    memset(&ep->ptls_ctx, 0, sizeof(ep->ptls_ctx));
    ep->ptls_ctx.random_bytes = ptls_openssl_random_bytes;
    ep->ptls_ctx.get_time = &ptls_get_time;
    ep->ptls_ctx.key_exchanges = net_quic_picotls_key_exchanges;
    ep->ptls_ctx.cipher_suites = net_quic_picotls_cipher_suites;
    ep->ptls_ctx.require_dhe_on_psk = 1;
}

static int
net_quic_tls_client_prepare(net_quic_connection *ep)
{
    net_quic_tls_context_defaults(ep);

    if (ngtcp2_crypto_picotls_configure_client_context(&ep->ptls_ctx) != 0) {
        return -1;
    }

    ngtcp2_crypto_picotls_ctx_init(&ep->picotls_ctx);
    ep->picotls_ctx.ptls = ptls_client_new(&ep->ptls_ctx);
    if (ep->picotls_ctx.ptls == NULL) {
        return -1;
    }

    *ptls_get_data_ptr(ep->picotls_ctx.ptls) = &ep->conn_ref;

    return 0;
}

static int
net_quic_tls_alloc_extensions(pTHX_ net_quic_connection *ep)
{
    Newxz(
        ep->picotls_ctx.handshake_properties.additional_extensions,
        2,
        ptls_raw_extension_t
    );
    if (ep->picotls_ctx.handshake_properties.additional_extensions == NULL) {
        return -1;
    }

    ep->picotls_ctx.handshake_properties.additional_extensions[0].type = UINT16_MAX;
    ep->picotls_ctx.handshake_properties.additional_extensions[1].type = UINT16_MAX;

    return 0;
}

static int
net_quic_tls_client_finish(pTHX_ net_quic_connection *ep)
{
    if (ep->alpnlen == 0 || ep->alpnlen > 255) {
        return -1;
    }

    if (net_quic_tls_alloc_extensions(aTHX_ ep) != 0) {
        return -1;
    }

    if (ngtcp2_crypto_picotls_configure_client_session(&ep->picotls_ctx, ep->conn) != 0) {
        return -1;
    }

    ep->picotls_alpn.base = (uint8_t *)ep->alpn;
    ep->picotls_alpn.len = ep->alpnlen;
    ep->picotls_ctx.handshake_properties.client.negotiated_protocols.list =
        &ep->picotls_alpn;
    ep->picotls_ctx.handshake_properties.client.negotiated_protocols.count = 1;

    if (ep->server_name[0] != '\0' &&
        ptls_set_server_name(
            ep->picotls_ctx.ptls,
            ep->server_name,
            strlen(ep->server_name)
        ) != 0) {
        return -1;
    }

    ngtcp2_conn_set_tls_native_handle(ep->conn, &ep->picotls_ctx);
    return 0;
}

static int
net_quic_tls_on_client_hello(
    ptls_on_client_hello_t *self,
    ptls_t *ptls,
    ptls_on_client_hello_parameters_t *params
)
{
    ngtcp2_crypto_conn_ref *conn_ref;
    net_quic_connection *ep;
    size_t i;

    (void)self;

    conn_ref = (ngtcp2_crypto_conn_ref *)*ptls_get_data_ptr(ptls);
    if (conn_ref == NULL || conn_ref->user_data == NULL) {
        return PTLS_ALERT_INTERNAL_ERROR;
    }

    ep = (net_quic_connection *)conn_ref->user_data;

    for (i = 0; i < params->negotiated_protocols.count; ++i) {
        ptls_iovec_t proto = params->negotiated_protocols.list[i];

        if (proto.len == ep->alpnlen &&
            memcmp(proto.base, ep->alpn, ep->alpnlen) == 0) {
            return ptls_set_negotiated_protocol(
                ptls,
                (const char *)proto.base,
                proto.len
            );
        }
    }

    return PTLS_ALERT_NO_APPLICATION_PROTOCOL;
}

static int
net_quic_tls_server_prepare(
    net_quic_connection *ep,
    const char *cert_file,
    const char *key_file
)
{
    FILE *fp;
    EVP_PKEY *pkey;

    net_quic_tls_context_defaults(ep);

    ep->picotls_on_client_hello.cb = net_quic_tls_on_client_hello;
    ep->ptls_ctx.on_client_hello = &ep->picotls_on_client_hello;

    if (ngtcp2_crypto_picotls_configure_server_context(&ep->ptls_ctx) != 0) {
        return -1;
    }

    if (ptls_load_certificates(&ep->ptls_ctx, cert_file) != 0) {
        return -1;
    }

    fp = fopen(key_file, "rb");
    if (fp == NULL) {
        return -1;
    }

    pkey = PEM_read_PrivateKey(fp, NULL, NULL, NULL);
    fclose(fp);
    if (pkey == NULL) {
        return -1;
    }

    if (ptls_openssl_init_sign_certificate(&ep->picotls_sign_cert, pkey) != 0) {
        EVP_PKEY_free(pkey);
        return -1;
    }
    EVP_PKEY_free(pkey);

    ep->ptls_ctx.sign_certificate = &ep->picotls_sign_cert.super;

    ngtcp2_crypto_picotls_ctx_init(&ep->picotls_ctx);
    ep->picotls_ctx.ptls = ptls_server_new(&ep->ptls_ctx);
    if (ep->picotls_ctx.ptls == NULL) {
        return -1;
    }

    *ptls_get_data_ptr(ep->picotls_ctx.ptls) = &ep->conn_ref;

    return 0;
}

static int
net_quic_tls_server_finish(pTHX_ net_quic_connection *ep)
{
    if (net_quic_tls_alloc_extensions(aTHX_ ep) != 0) {
        return -1;
    }

    if (ngtcp2_crypto_picotls_configure_server_session(&ep->picotls_ctx) != 0) {
        return -1;
    }

    ngtcp2_conn_set_tls_native_handle(ep->conn, &ep->picotls_ctx);
    return 0;
}

static void
net_quic_tls_cleanup(pTHX_ net_quic_connection *ep)
{
    size_t i;

    ngtcp2_crypto_picotls_deconfigure_session(&ep->picotls_ctx);
    Safefree(ep->picotls_ctx.handshake_properties.additional_extensions);
    ep->picotls_ctx.handshake_properties.additional_extensions = NULL;

    if (ep->picotls_ctx.ptls != NULL) {
        *ptls_get_data_ptr(ep->picotls_ctx.ptls) = NULL;
        ptls_free(ep->picotls_ctx.ptls);
        ep->picotls_ctx.ptls = NULL;
    }

    if (ep->picotls_sign_cert.key != NULL) {
        ptls_openssl_dispose_sign_certificate(&ep->picotls_sign_cert);
    }

    for (i = 0; i < ep->ptls_ctx.certificates.count; ++i) {
        free(ep->ptls_ctx.certificates.list[i].base);
    }
    free(ep->ptls_ctx.certificates.list);
    ep->ptls_ctx.certificates.list = NULL;
    ep->ptls_ctx.certificates.count = 0;
}
