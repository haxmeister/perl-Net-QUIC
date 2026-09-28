#if defined(NET_QUIC_CRYPTO_PICOTLS)
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
#endif

static int
net_quic_tls_prepare(net_quic_endpoint *ep)
{
#if defined(NET_QUIC_CRYPTO_OPENSSL)
    ep->ssl_ctx = SSL_CTX_new(TLS_client_method());
    if (ep->ssl_ctx == NULL) {
        return -1;
    }

    SSL_CTX_set_default_verify_paths(ep->ssl_ctx);

    ep->ssl = SSL_new(ep->ssl_ctx);
    if (ep->ssl == NULL) {
        return -1;
    }

    if (ngtcp2_crypto_ossl_ctx_new(&ep->ossl_ctx, NULL) != 0) {
        return -1;
    }

    ngtcp2_crypto_ossl_ctx_set_ssl(ep->ossl_ctx, ep->ssl);

    if (ngtcp2_crypto_ossl_configure_client_session(ep->ssl) != 0) {
        return -1;
    }

    SSL_set_app_data(ep->ssl, &ep->conn_ref);
    SSL_set_connect_state(ep->ssl);

    return 0;
#elif defined(NET_QUIC_CRYPTO_GNUTLS)
    if (gnutls_certificate_allocate_credentials(&ep->cred) != 0) {
        return -1;
    }

    if (gnutls_certificate_set_x509_system_trust(ep->cred) < 0) {
        return -1;
    }

    if (gnutls_init(&ep->session, GNUTLS_CLIENT) != 0) {
        return -1;
    }

    if (gnutls_set_default_priority(ep->session) != 0) {
        return -1;
    }

    if (ngtcp2_crypto_gnutls_configure_client_session(ep->session) != 0) {
        return -1;
    }

    gnutls_session_set_ptr(ep->session, &ep->conn_ref);

    if (gnutls_credentials_set(ep->session, GNUTLS_CRD_CERTIFICATE, ep->cred) != 0) {
        return -1;
    }

    return 0;
#elif defined(NET_QUIC_CRYPTO_BORINGSSL)
    ep->ssl_ctx = SSL_CTX_new(TLS_client_method());
    if (ep->ssl_ctx == NULL) {
        return -1;
    }

    if (ngtcp2_crypto_boringssl_configure_client_context(ep->ssl_ctx) != 0) {
        return -1;
    }

    SSL_CTX_set_default_verify_paths(ep->ssl_ctx);

    ep->ssl = SSL_new(ep->ssl_ctx);
    if (ep->ssl == NULL) {
        return -1;
    }

    SSL_set_app_data(ep->ssl, &ep->conn_ref);
    SSL_set_connect_state(ep->ssl);

    return 0;
#elif defined(NET_QUIC_CRYPTO_WOLFSSL)
    ep->ssl_ctx = wolfSSL_CTX_new(wolfTLSv1_3_client_method());
    if (ep->ssl_ctx == NULL) {
        return -1;
    }

    if (ngtcp2_crypto_wolfssl_configure_client_context(ep->ssl_ctx) != 0) {
        return -1;
    }

    wolfSSL_CTX_set_default_verify_paths(ep->ssl_ctx);

    ep->ssl = wolfSSL_new(ep->ssl_ctx);
    if (ep->ssl == NULL) {
        return -1;
    }

    wolfSSL_set_app_data(ep->ssl, &ep->conn_ref);
    wolfSSL_set_connect_state(ep->ssl);
    wolfSSL_set_quic_transport_version(ep->ssl, NGTCP2_TLSEXT_QUIC_TRANSPORT_PARAMETERS_V1);

    return 0;
#elif defined(NET_QUIC_CRYPTO_PICOTLS)
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
#else
    return -1;
#endif
}

static int
net_quic_tls_finish(pTHX_ net_quic_endpoint *ep)
{
    unsigned char alpn_wire[256];

    if (ep->alpnlen == 0 || ep->alpnlen > 255) {
        return -1;
    }

#if defined(NET_QUIC_CRYPTO_OPENSSL)
    alpn_wire[0] = (unsigned char)ep->alpnlen;
    memcpy(alpn_wire + 1, ep->alpn, ep->alpnlen);

    if (SSL_set_alpn_protos(ep->ssl, alpn_wire, (unsigned int)ep->alpnlen + 1) != 0) {
        return -1;
    }

    if (ep->server_name[0] != '\0' &&
        SSL_set_tlsext_host_name(ep->ssl, ep->server_name) != 1) {
        return -1;
    }

    ngtcp2_conn_set_tls_native_handle(ep->conn, ep->ossl_ctx);
    return 0;
#elif defined(NET_QUIC_CRYPTO_GNUTLS)
    {
        gnutls_datum_t alpn;
        alpn.data = (unsigned char *)ep->alpn;
        alpn.size = (unsigned int)ep->alpnlen;

        if (gnutls_alpn_set_protocols(ep->session, &alpn, 1, GNUTLS_ALPN_MANDATORY) != 0) {
            return -1;
        }
    }

    if (ep->server_name[0] != '\0' &&
        gnutls_server_name_set(
            ep->session,
            GNUTLS_NAME_DNS,
            ep->server_name,
            strlen(ep->server_name)
        ) != 0) {
        return -1;
    }

    ngtcp2_conn_set_tls_native_handle(ep->conn, ep->session);
    return 0;
#elif defined(NET_QUIC_CRYPTO_BORINGSSL)
    alpn_wire[0] = (unsigned char)ep->alpnlen;
    memcpy(alpn_wire + 1, ep->alpn, ep->alpnlen);

    if (SSL_set_alpn_protos(ep->ssl, alpn_wire, ep->alpnlen + 1) != 0) {
        return -1;
    }

    if (ep->server_name[0] != '\0' &&
        SSL_set_tlsext_host_name(ep->ssl, ep->server_name) != 1) {
        return -1;
    }

    ngtcp2_conn_set_tls_native_handle(ep->conn, ep->ssl);
    return 0;
#elif defined(NET_QUIC_CRYPTO_WOLFSSL)
    alpn_wire[0] = (unsigned char)ep->alpnlen;
    memcpy(alpn_wire + 1, ep->alpn, ep->alpnlen);

    if (wolfSSL_set_alpn_protos(ep->ssl, alpn_wire, (unsigned int)ep->alpnlen + 1) != WOLFSSL_SUCCESS) {
        return -1;
    }

    if (ep->server_name[0] != '\0' &&
        wolfSSL_UseSNI(
            ep->ssl,
            WOLFSSL_SNI_HOST_NAME,
            ep->server_name,
            (unsigned short)strlen(ep->server_name)
        ) != WOLFSSL_SUCCESS) {
        return -1;
    }

    ngtcp2_conn_set_tls_native_handle(ep->conn, ep->ssl);
    return 0;
#elif defined(NET_QUIC_CRYPTO_PICOTLS)
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
#else
    return -1;
#endif
}

static void
net_quic_tls_cleanup(pTHX_ net_quic_endpoint *ep)
{
#if defined(NET_QUIC_CRYPTO_OPENSSL)
    if (ep->ssl != NULL) {
        SSL_set_app_data(ep->ssl, NULL);
        SSL_free(ep->ssl);
        ep->ssl = NULL;
    }
    if (ep->ossl_ctx != NULL) {
        ngtcp2_crypto_ossl_ctx_del(ep->ossl_ctx);
        ep->ossl_ctx = NULL;
    }
    if (ep->ssl_ctx != NULL) {
        SSL_CTX_free(ep->ssl_ctx);
        ep->ssl_ctx = NULL;
    }
#elif defined(NET_QUIC_CRYPTO_GNUTLS)
    if (ep->session != NULL) {
        gnutls_session_set_ptr(ep->session, NULL);
        gnutls_deinit(ep->session);
        ep->session = NULL;
    }
    if (ep->cred != NULL) {
        gnutls_certificate_free_credentials(ep->cred);
        ep->cred = NULL;
    }
#elif defined(NET_QUIC_CRYPTO_BORINGSSL)
    if (ep->ssl != NULL) {
        SSL_set_app_data(ep->ssl, NULL);
        SSL_free(ep->ssl);
        ep->ssl = NULL;
    }
    if (ep->ssl_ctx != NULL) {
        SSL_CTX_free(ep->ssl_ctx);
        ep->ssl_ctx = NULL;
    }
#elif defined(NET_QUIC_CRYPTO_WOLFSSL)
    if (ep->ssl != NULL) {
        wolfSSL_set_app_data(ep->ssl, NULL);
        wolfSSL_free(ep->ssl);
        ep->ssl = NULL;
    }
    if (ep->ssl_ctx != NULL) {
        wolfSSL_CTX_free(ep->ssl_ctx);
        ep->ssl_ctx = NULL;
    }
#elif defined(NET_QUIC_CRYPTO_PICOTLS)
    ngtcp2_crypto_picotls_deconfigure_session(&ep->picotls_ctx);
    Safefree(ep->picotls_ctx.handshake_properties.additional_extensions);
    ep->picotls_ctx.handshake_properties.additional_extensions = NULL;
    if (ep->picotls_ctx.ptls != NULL) {
        *ptls_get_data_ptr(ep->picotls_ctx.ptls) = NULL;
        ptls_free(ep->picotls_ctx.ptls);
        ep->picotls_ctx.ptls = NULL;
    }
#endif

}
