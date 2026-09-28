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

static int
net_quic_tls_prepare(net_quic_connection *ep)
{
    memset(&ep->ptls_ctx, 0, sizeof(ep->ptls_ctx));
    ep->ptls_ctx.random_bytes = ptls_openssl_random_bytes;
    ep->ptls_ctx.get_time = &ptls_get_time;
    ep->ptls_ctx.key_exchanges = net_quic_picotls_key_exchanges;
    ep->ptls_ctx.cipher_suites = net_quic_picotls_cipher_suites;
    ep->ptls_ctx.require_dhe_on_psk = 1;

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
net_quic_tls_finish(pTHX_ net_quic_connection *ep)
{
    if (ep->alpnlen == 0 || ep->alpnlen > 255) {
        return -1;
    }

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

static void
net_quic_tls_cleanup(pTHX_ net_quic_connection *ep)
{
    ngtcp2_crypto_picotls_deconfigure_session(&ep->picotls_ctx);
    Safefree(ep->picotls_ctx.handshake_properties.additional_extensions);
    ep->picotls_ctx.handshake_properties.additional_extensions = NULL;

    if (ep->picotls_ctx.ptls != NULL) {
        *ptls_get_data_ptr(ep->picotls_ctx.ptls) = NULL;
        ptls_free(ep->picotls_ctx.ptls);
        ep->picotls_ctx.ptls = NULL;
    }
}
