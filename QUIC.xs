#include "xs/net_quic_connection.h"

MODULE = Net::QUIC    PACKAGE = Net::QUIC

PROTOTYPES: DISABLE

const char *
ngtcp2_version()
    PREINIT:
        const ngtcp2_info *info;
    CODE:
        info = ngtcp2_version(0);
        if (info == NULL || info->version_str == NULL) {
            croak("ngtcp2 did not report a version");
        }
        RETVAL = info->version_str;
    OUTPUT:
        RETVAL

int
ngtcp2_version_num()
    PREINIT:
        const ngtcp2_info *info;
    CODE:
        info = ngtcp2_version(0);
        if (info == NULL) {
            croak("ngtcp2 did not report version information");
        }
        RETVAL = info->version_num;
    OUTPUT:
        RETVAL

const char *
crypto_backend()
    CODE:
        RETVAL = net_quic_crypto_backend();
    OUTPUT:
        RETVAL

int
_crypto_self_test()
    PREINIT:
        uint8_t token[NGTCP2_STATELESS_RESET_TOKENLEN];
        uint8_t secret[32];
        ngtcp2_cid cid;
        int rv;
    CODE:
        memset(token, 0, sizeof(token));
        memset(secret, 0, sizeof(secret));
        memset(&cid, 0, sizeof(cid));

        cid.datalen = 8;

        rv = ngtcp2_crypto_generate_stateless_reset_token(
            token,
            secret,
            sizeof(secret),
            &cid
        );

        RETVAL = rv == 0 ? 1 : 0;
    OUTPUT:
        RETVAL

MODULE = Net::QUIC    PACKAGE = Net::QUIC::Connection

SV *
_client_new(class, local_sv, peer_sv, alpn_sv, server_name_sv)
    const char *class
    SV *local_sv
    SV *peer_sv
    SV *alpn_sv
    SV *server_name_sv
    PREINIT:
        net_quic_connection *ep = NULL;
        const char *local;
        const char *peer;
        const char *alpn;
        const char *server_name;
        STRLEN locallen;
        STRLEN peerlen;
        STRLEN alpnlen;
        STRLEN server_namelen;
        ngtcp2_callbacks callbacks;
        ngtcp2_settings settings;
        ngtcp2_transport_params params;
        ngtcp2_path path;
        ngtcp2_cid dcid;
        ngtcp2_cid scid;
        int rv;
    CODE:
        local = SvPVbyte(local_sv, locallen);
        peer = SvPVbyte(peer_sv, peerlen);
        alpn = SvPVbyte(alpn_sv, alpnlen);
        server_name = SvPVbyte(server_name_sv, server_namelen);

        if (alpnlen == 0 || alpnlen > 255) {
            croak("alpn must contain 1 to 255 bytes");
        }
        if (server_namelen > 255 ||
            memchr(server_name, '\0', (size_t)server_namelen) != NULL) {
            croak("server_name must be at most 255 bytes and cannot contain NUL");
        }

        Newxz(ep, 1, net_quic_connection);
        if (ep == NULL) {
            croak("unable to allocate Net::QUIC::Connection");
        }

        if (net_quic_copy_sockaddr(
                &ep->local_addr,
                &ep->local_addrlen,
                local,
                locallen
            ) != 0) {
            net_quic_connection_free(aTHX_ ep);
            croak("local must be a packed IPv4 or IPv6 socket address");
        }

        if (net_quic_copy_sockaddr(
                &ep->peer_addr,
                &ep->peer_addrlen,
                peer,
                peerlen
            ) != 0) {
            net_quic_connection_free(aTHX_ ep);
            croak("peer must be a packed IPv4 or IPv6 socket address");
        }

        ep->alpn = net_quic_strdup_len(aTHX_ alpn, (size_t)alpnlen);
        ep->alpnlen = (size_t)alpnlen;
        ep->server_name = net_quic_strdup_len(aTHX_ server_name, (size_t)server_namelen);
        if (ep->alpn == NULL || ep->server_name == NULL) {
            net_quic_connection_free(aTHX_ ep);
            croak("unable to allocate Net::QUIC::Connection strings");
        }

        ep->conn_ref.get_conn = net_quic_get_conn;
        ep->conn_ref.user_data = ep;

        if (net_quic_tls_client_prepare(ep) != 0) {
            net_quic_connection_free(aTHX_ ep);
            croak("unable to initialize Picotls for QUIC");
        }

        memset(&callbacks, 0, sizeof(callbacks));
        callbacks.client_initial = ngtcp2_crypto_client_initial_cb;
        callbacks.recv_crypto_data = ngtcp2_crypto_recv_crypto_data_cb;
        callbacks.handshake_completed = net_quic_handshake_completed_cb;
        callbacks.encrypt = ngtcp2_crypto_encrypt_cb;
        callbacks.decrypt = ngtcp2_crypto_decrypt_cb;
        callbacks.hp_mask = ngtcp2_crypto_hp_mask_cb;
        callbacks.recv_retry = ngtcp2_crypto_recv_retry_cb;
        callbacks.rand = net_quic_rand_cb;
        callbacks.update_key = ngtcp2_crypto_update_key_cb;
        callbacks.delete_crypto_aead_ctx = ngtcp2_crypto_delete_crypto_aead_ctx_cb;
        callbacks.delete_crypto_cipher_ctx = ngtcp2_crypto_delete_crypto_cipher_ctx_cb;
        callbacks.version_negotiation = ngtcp2_crypto_version_negotiation_cb;
        callbacks.get_new_connection_id2 = net_quic_get_new_connection_id_cb;
        callbacks.get_path_challenge_data2 = ngtcp2_crypto_get_path_challenge_data2_cb;

        if (net_quic_random_bytes(dcid.data, NGTCP2_MIN_INITIAL_DCIDLEN) != 0 ||
            net_quic_random_bytes(scid.data, 16) != 0) {
            net_quic_connection_free(aTHX_ ep);
            croak("unable to generate QUIC connection IDs");
        }
        dcid.datalen = NGTCP2_MIN_INITIAL_DCIDLEN;
        scid.datalen = 16;

        ngtcp2_settings_default(&settings);
        settings.initial_ts = net_quic_now();

        ngtcp2_transport_params_default(&params);
        params.initial_max_stream_data_bidi_local = 256 * 1024;
        params.initial_max_stream_data_bidi_remote = 256 * 1024;
        params.initial_max_stream_data_uni = 256 * 1024;
        params.initial_max_data = 1024 * 1024;
        params.initial_max_streams_bidi = 100;
        params.initial_max_streams_uni = 100;
        params.active_connection_id_limit = 4;

        memset(&path, 0, sizeof(path));
        path.local.addr = &ep->local_addr.sa;
        path.local.addrlen = ep->local_addrlen;
        path.remote.addr = &ep->peer_addr.sa;
        path.remote.addrlen = ep->peer_addrlen;

        rv = ngtcp2_conn_client_new(
            &ep->conn,
            &dcid,
            &scid,
            &path,
            NGTCP2_PROTO_VER_V1,
            &callbacks,
            &settings,
            &params,
            NULL,
            ep
        );
        if (rv != 0) {
            net_quic_connection_free(aTHX_ ep);
            croak("ngtcp2_conn_client_new failed: %s", ngtcp2_strerror(rv));
        }

        if (net_quic_tls_client_finish(aTHX_ ep) != 0) {
            net_quic_connection_free(aTHX_ ep);
            croak("unable to configure Picotls for QUIC");
        }

        RETVAL = net_quic_connection_bless(class, ep);
    OUTPUT:
        RETVAL

SV *
_server_new(class, initial_sv, local_sv, peer_sv, alpn_sv, cert_file_sv, key_file_sv)
    const char *class
    SV *initial_sv
    SV *local_sv
    SV *peer_sv
    SV *alpn_sv
    SV *cert_file_sv
    SV *key_file_sv
    PREINIT:
        net_quic_connection *ep = NULL;
        const char *initial;
        const char *local;
        const char *peer;
        const char *alpn;
        const char *cert_file;
        const char *key_file;
        STRLEN initiallen;
        STRLEN locallen;
        STRLEN peerlen;
        STRLEN alpnlen;
        STRLEN cert_file_len;
        STRLEN key_file_len;
        ngtcp2_version_cid vcid;
        ngtcp2_pkt_hd hd;
        ngtcp2_callbacks callbacks;
        ngtcp2_settings settings;
        ngtcp2_transport_params params;
        ngtcp2_path path;
        ngtcp2_cid dcid;
        ngtcp2_cid scid;
        int rv;
    CODE:
        initial = SvPVbyte(initial_sv, initiallen);
        local = SvPVbyte(local_sv, locallen);
        peer = SvPVbyte(peer_sv, peerlen);
        alpn = SvPVbyte(alpn_sv, alpnlen);
        cert_file = SvPVbyte(cert_file_sv, cert_file_len);
        key_file = SvPVbyte(key_file_sv, key_file_len);

        if (alpnlen == 0 || alpnlen > 255) {
            croak("alpn must contain 1 to 255 bytes");
        }
        if (memchr(cert_file, '\0', (size_t)cert_file_len) != NULL ||
            memchr(key_file, '\0', (size_t)key_file_len) != NULL) {
            croak("certificate and key paths cannot contain NUL");
        }

        memset(&vcid, 0, sizeof(vcid));
        rv = ngtcp2_pkt_decode_version_cid(
            &vcid,
            (const uint8_t *)initial,
            (size_t)initiallen,
            0
        );
        if (rv != 0) {
            croak("unable to decode client Initial connection IDs: %s", ngtcp2_strerror(rv));
        }

        memset(&hd, 0, sizeof(hd));
        rv = ngtcp2_accept(&hd, (const uint8_t *)initial, (size_t)initiallen);
        if (rv != 0) {
            croak("packet is not an acceptable QUIC Initial");
        }

        if (vcid.scidlen == 0 ||
            vcid.scidlen > NGTCP2_MAX_CIDLEN ||
            vcid.dcidlen > NGTCP2_MAX_CIDLEN) {
            croak("client Initial contains unsupported connection IDs");
        }

        Newxz(ep, 1, net_quic_connection);
        if (ep == NULL) {
            croak("unable to allocate Net::QUIC::Connection");
        }
        ep->is_server = 1;

        if (net_quic_copy_sockaddr(
                &ep->local_addr,
                &ep->local_addrlen,
                local,
                locallen
            ) != 0) {
            net_quic_connection_free(aTHX_ ep);
            croak("local must be a packed IPv4 or IPv6 socket address");
        }

        if (net_quic_copy_sockaddr(
                &ep->peer_addr,
                &ep->peer_addrlen,
                peer,
                peerlen
            ) != 0) {
            net_quic_connection_free(aTHX_ ep);
            croak("peer must be a packed IPv4 or IPv6 socket address");
        }

        ep->alpn = net_quic_strdup_len(aTHX_ alpn, (size_t)alpnlen);
        ep->alpnlen = (size_t)alpnlen;
        if (ep->alpn == NULL) {
            net_quic_connection_free(aTHX_ ep);
            croak("unable to allocate Net::QUIC::Connection ALPN");
        }

        ep->conn_ref.get_conn = net_quic_get_conn;
        ep->conn_ref.user_data = ep;

        if (net_quic_tls_server_prepare(ep, cert_file, key_file) != 0) {
            net_quic_connection_free(aTHX_ ep);
            croak("unable to initialize Picotls server credentials");
        }

        memset(&callbacks, 0, sizeof(callbacks));
        callbacks.recv_client_initial = ngtcp2_crypto_recv_client_initial_cb;
        callbacks.recv_crypto_data = ngtcp2_crypto_recv_crypto_data_cb;
        callbacks.handshake_completed = net_quic_handshake_completed_cb;
        callbacks.encrypt = ngtcp2_crypto_encrypt_cb;
        callbacks.decrypt = ngtcp2_crypto_decrypt_cb;
        callbacks.hp_mask = ngtcp2_crypto_hp_mask_cb;
        callbacks.rand = net_quic_rand_cb;
        callbacks.update_key = ngtcp2_crypto_update_key_cb;
        callbacks.delete_crypto_aead_ctx = ngtcp2_crypto_delete_crypto_aead_ctx_cb;
        callbacks.delete_crypto_cipher_ctx = ngtcp2_crypto_delete_crypto_cipher_ctx_cb;
        callbacks.version_negotiation = ngtcp2_crypto_version_negotiation_cb;
        callbacks.get_new_connection_id2 = net_quic_get_new_connection_id_cb;
        callbacks.get_path_challenge_data2 = ngtcp2_crypto_get_path_challenge_data2_cb;

        ngtcp2_cid_init(&dcid, vcid.scid, vcid.scidlen);

        scid.datalen = 16;
        if (net_quic_random_bytes(scid.data, scid.datalen) != 0) {
            net_quic_connection_free(aTHX_ ep);
            croak("unable to generate server QUIC connection ID");
        }

        ngtcp2_settings_default(&settings);
        settings.initial_ts = net_quic_now();

        ngtcp2_transport_params_default(&params);
        params.initial_max_stream_data_bidi_local = 256 * 1024;
        params.initial_max_stream_data_bidi_remote = 256 * 1024;
        params.initial_max_stream_data_uni = 256 * 1024;
        params.initial_max_data = 1024 * 1024;
        params.initial_max_streams_bidi = 100;
        params.initial_max_streams_uni = 100;
        params.active_connection_id_limit = 4;
        ngtcp2_cid_init(&params.original_dcid, vcid.dcid, vcid.dcidlen);
        params.original_dcid_present = 1;

        memset(&path, 0, sizeof(path));
        path.local.addr = &ep->local_addr.sa;
        path.local.addrlen = ep->local_addrlen;
        path.remote.addr = &ep->peer_addr.sa;
        path.remote.addrlen = ep->peer_addrlen;

        rv = ngtcp2_conn_server_new(
            &ep->conn,
            &dcid,
            &scid,
            &path,
            vcid.version,
            &callbacks,
            &settings,
            &params,
            NULL,
            ep
        );
        if (rv != 0) {
            net_quic_connection_free(aTHX_ ep);
            croak("ngtcp2_conn_server_new failed: %s", ngtcp2_strerror(rv));
        }

        if (net_quic_tls_server_finish(aTHX_ ep) != 0) {
            net_quic_connection_free(aTHX_ ep);
            croak("unable to configure Picotls server session");
        }

        RETVAL = net_quic_connection_bless(class, ep);
    OUTPUT:
        RETVAL

SV *
_next_datagram(self)
    SV *self
    PREINIT:
        net_quic_connection *ep;
        ngtcp2_path_storage ps;
        ngtcp2_pkt_info pi;
        ngtcp2_ssize nwrite;
        ngtcp2_tstamp now;
    CODE:
        ep = net_quic_connection_from_sv(self);
        ngtcp2_path_storage_zero(&ps);
        memset(&pi, 0, sizeof(pi));

        now = net_quic_now();
        nwrite = ngtcp2_conn_write_pkt(
            ep->conn,
            &ps.path,
            &pi,
            ep->txbuf,
            sizeof(ep->txbuf),
            now
        );

        if (nwrite < 0) {
            croak("ngtcp2_conn_write_pkt failed: %s", ngtcp2_strerror((int)nwrite));
        }

        if (nwrite == 0) {
            RETVAL = &PL_sv_undef;
        } else {
            if (ps.path.local.addr == NULL || ps.path.remote.addr == NULL) {
                croak("ngtcp2 produced a datagram without a network path");
            }

            ngtcp2_conn_update_pkt_tx_time(ep->conn, now);
            RETVAL = net_quic_datagram_new(
                ep->txbuf,
                (size_t)nwrite,
                &ps.path.local,
                &ps.path.remote
            );
        }
    OUTPUT:
        RETVAL

void
_receive_datagram(self, data_sv, local_sv, peer_sv)
    SV *self
    SV *data_sv
    SV *local_sv
    SV *peer_sv
    PREINIT:
        net_quic_connection *ep;
        const char *data;
        const char *local;
        const char *peer;
        STRLEN datalen;
        STRLEN locallen;
        STRLEN peerlen;
        ngtcp2_sockaddr_union local_addr;
        ngtcp2_socklen local_addrlen;
        ngtcp2_sockaddr_union peer_addr;
        ngtcp2_socklen peer_addrlen;
        ngtcp2_path path;
        ngtcp2_pkt_info pi;
        int rv;
    CODE:
        ep = net_quic_connection_from_sv(self);
        data = SvPVbyte(data_sv, datalen);
        local = SvPVbyte(local_sv, locallen);
        peer = SvPVbyte(peer_sv, peerlen);

        if (net_quic_copy_sockaddr(&local_addr, &local_addrlen, local, locallen) != 0 ||
            net_quic_copy_sockaddr(&peer_addr, &peer_addrlen, peer, peerlen) != 0) {
            croak("local and peer must be packed IPv4 or IPv6 socket addresses");
        }

        memset(&path, 0, sizeof(path));
        path.local.addr = &local_addr.sa;
        path.local.addrlen = local_addrlen;
        path.remote.addr = &peer_addr.sa;
        path.remote.addrlen = peer_addrlen;
        memset(&pi, 0, sizeof(pi));

        rv = ngtcp2_conn_read_pkt(
            ep->conn,
            &path,
            &pi,
            (const uint8_t *)data,
            (size_t)datalen,
            net_quic_now()
        );
        if (rv != 0) {
            croak("ngtcp2_conn_read_pkt failed: %s", ngtcp2_strerror(rv));
        }

SV *
_timeout_after(self)
    SV *self
    PREINIT:
        net_quic_connection *ep;
        ngtcp2_tstamp expiry;
        ngtcp2_tstamp now;
        NV seconds;
    CODE:
        ep = net_quic_connection_from_sv(self);
        expiry = ngtcp2_conn_get_expiry2(ep->conn);

        if (expiry == UINT64_MAX) {
            RETVAL = &PL_sv_undef;
        } else {
            now = net_quic_now();
            seconds = expiry <= now
                ? 0.0
                : (NV)(expiry - now) / (NV)NGTCP2_SECONDS;
            RETVAL = newSVnv(seconds);
        }
    OUTPUT:
        RETVAL

void
_handle_timeout(self)
    SV *self
    PREINIT:
        net_quic_connection *ep;
        int rv;
    CODE:
        ep = net_quic_connection_from_sv(self);
        rv = ngtcp2_conn_handle_expiry(ep->conn, net_quic_now());
        if (rv != 0) {
            croak("ngtcp2_conn_handle_expiry failed: %s", ngtcp2_strerror(rv));
        }

int
ready(self)
    SV *self
    PREINIT:
        net_quic_connection *ep;
    CODE:
        ep = net_quic_connection_from_sv(self);
        RETVAL = ep->ready ? 1 : 0;
    OUTPUT:
        RETVAL

void
DESTROY(self)
    SV *self
    PREINIT:
        net_quic_connection *ep;
        SV *inner;
    CODE:
        if (!SvROK(self)) {
            XSRETURN_EMPTY;
        }

        inner = SvRV(self);
        ep = INT2PTR(net_quic_connection *, SvIV(inner));
        if (ep != NULL) {
            net_quic_connection_free(aTHX_ ep);
            sv_setiv(inner, 0);
        }
