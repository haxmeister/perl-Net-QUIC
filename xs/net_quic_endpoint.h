#include "EXTERN.h"
#include "perl.h"
#include "XSUB.h"

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <ngtcp2/ngtcp2.h>
#include <ngtcp2/ngtcp2_crypto.h>

#if defined(_WIN32) || defined(WIN32)
# include <windows.h>
#else
# include <time.h>
#endif

#if defined(NET_QUIC_CRYPTO_OPENSSL)
# include <ngtcp2/ngtcp2_crypto_ossl.h>
# include <openssl/rand.h>
# include <openssl/ssl.h>
#elif defined(NET_QUIC_CRYPTO_GNUTLS)
# include <ngtcp2/ngtcp2_crypto_gnutls.h>
# include <gnutls/crypto.h>
# include <gnutls/gnutls.h>
#elif defined(NET_QUIC_CRYPTO_BORINGSSL)
# include <ngtcp2/ngtcp2_crypto_boringssl.h>
# include <openssl/rand.h>
# include <openssl/ssl.h>
#elif defined(NET_QUIC_CRYPTO_WOLFSSL)
# include <ngtcp2/ngtcp2_crypto_wolfssl.h>
# include <wolfssl/options.h>
# include <wolfssl/ssl.h>
# include <wolfssl/quic.h>
#elif defined(NET_QUIC_CRYPTO_PICOTLS)
# include <ngtcp2/ngtcp2_crypto_picotls.h>
# include <openssl/rand.h>
# include <picotls.h>
# include <picotls/openssl.h>
#endif

#define NET_QUIC_TX_BUFSIZE 65536

static const char *
net_quic_crypto_backend(void)
{
#if defined(NET_QUIC_CRYPTO_OPENSSL)
    return "openssl";
#elif defined(NET_QUIC_CRYPTO_GNUTLS)
    return "gnutls";
#elif defined(NET_QUIC_CRYPTO_BORINGSSL)
    return "boringssl";
#elif defined(NET_QUIC_CRYPTO_WOLFSSL)
    return "wolfssl";
#elif defined(NET_QUIC_CRYPTO_PICOTLS)
    return "picotls";
#else
# error "Net::QUIC was built without a supported crypto backend"
#endif
}

typedef struct net_quic_endpoint net_quic_endpoint;

struct net_quic_endpoint {
    ngtcp2_conn *conn;
    ngtcp2_crypto_conn_ref conn_ref;

    ngtcp2_sockaddr_union local_addr;
    ngtcp2_socklen local_addrlen;
    ngtcp2_sockaddr_union peer_addr;
    ngtcp2_socklen peer_addrlen;

    char *alpn;
    size_t alpnlen;
    char *server_name;
    int ready;

    uint8_t txbuf[NET_QUIC_TX_BUFSIZE];

#if defined(NET_QUIC_CRYPTO_OPENSSL)
    SSL_CTX *ssl_ctx;
    SSL *ssl;
    ngtcp2_crypto_ossl_ctx *ossl_ctx;
#elif defined(NET_QUIC_CRYPTO_GNUTLS)
    gnutls_certificate_credentials_t cred;
    gnutls_session_t session;
#elif defined(NET_QUIC_CRYPTO_BORINGSSL)
    SSL_CTX *ssl_ctx;
    SSL *ssl;
#elif defined(NET_QUIC_CRYPTO_WOLFSSL)
    WOLFSSL_CTX *ssl_ctx;
    WOLFSSL *ssl;
#elif defined(NET_QUIC_CRYPTO_PICOTLS)
    ptls_context_t ptls_ctx;
    ngtcp2_crypto_picotls_ctx picotls_ctx;
    ptls_iovec_t picotls_alpn;
#endif
};

static ngtcp2_tstamp
net_quic_now(void)
{
#if defined(_WIN32) || defined(WIN32)
    LARGE_INTEGER freq;
    LARGE_INTEGER counter;
    uint64_t whole;
    uint64_t rem;

    if (!QueryPerformanceFrequency(&freq) || !QueryPerformanceCounter(&counter)) {
        croak("unable to read monotonic clock");
    }

    whole = (uint64_t)counter.QuadPart / (uint64_t)freq.QuadPart;
    rem = (uint64_t)counter.QuadPart % (uint64_t)freq.QuadPart;

    return whole * NGTCP2_SECONDS
         + rem * NGTCP2_SECONDS / (uint64_t)freq.QuadPart;
#else
    struct timespec ts;

    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) {
        croak("unable to read monotonic clock");
    }

    return (ngtcp2_tstamp)ts.tv_sec * NGTCP2_SECONDS
         + (ngtcp2_tstamp)ts.tv_nsec;
#endif
}

static int
net_quic_random_bytes(uint8_t *dest, size_t destlen)
{
#if defined(NET_QUIC_CRYPTO_OPENSSL) || \
    defined(NET_QUIC_CRYPTO_BORINGSSL) || \
    defined(NET_QUIC_CRYPTO_PICOTLS)
    return RAND_bytes(dest, (int)destlen) == 1 ? 0 : -1;
#elif defined(NET_QUIC_CRYPTO_GNUTLS)
    return gnutls_rnd(GNUTLS_RND_RANDOM, dest, destlen) == 0 ? 0 : -1;
#elif defined(NET_QUIC_CRYPTO_WOLFSSL)
    return wolfSSL_RAND_bytes(dest, (int)destlen) == 1 ? 0 : -1;
#else
    return -1;
#endif
}

static void
net_quic_rand_cb(uint8_t *dest, size_t destlen, const ngtcp2_rand_ctx *rand_ctx)
{
    (void)rand_ctx;

    if (net_quic_random_bytes(dest, destlen) != 0) {
        abort();
    }
}

static int
net_quic_get_new_connection_id_cb(
    ngtcp2_conn *conn,
    ngtcp2_cid *cid,
    ngtcp2_stateless_reset_token *token,
    size_t cidlen,
    void *user_data
)
{
    (void)conn;
    (void)user_data;

    if (cidlen > sizeof(cid->data)) {
        return NGTCP2_ERR_CALLBACK_FAILURE;
    }

    if (net_quic_random_bytes(cid->data, cidlen) != 0) {
        return NGTCP2_ERR_CALLBACK_FAILURE;
    }

    cid->datalen = cidlen;

    if (net_quic_random_bytes(token->data, sizeof(token->data)) != 0) {
        return NGTCP2_ERR_CALLBACK_FAILURE;
    }

    return 0;
}

static int
net_quic_handshake_completed_cb(ngtcp2_conn *conn, void *user_data)
{
    net_quic_endpoint *ep = (net_quic_endpoint *)user_data;
    (void)conn;

    ep->ready = 1;
    return 0;
}

static ngtcp2_conn *
net_quic_get_conn(ngtcp2_crypto_conn_ref *conn_ref)
{
    net_quic_endpoint *ep = (net_quic_endpoint *)conn_ref->user_data;
    return ep->conn;
}

static int
net_quic_copy_sockaddr(
    ngtcp2_sockaddr_union *dest,
    ngtcp2_socklen *destlen,
    const char *src,
    STRLEN srclen
)
{
    ngtcp2_sockaddr *sa;

    if (srclen < sizeof(dest->sa.sa_family) || srclen > sizeof(*dest)) {
        return -1;
    }

    memset(dest, 0, sizeof(*dest));
    memcpy(dest, src, (size_t)srclen);

    sa = &dest->sa;
    if (sa->sa_family != NGTCP2_AF_INET && sa->sa_family != NGTCP2_AF_INET6) {
        return -1;
    }

    *destlen = (ngtcp2_socklen)srclen;
    return 0;
}

static char *
net_quic_strdup_len(pTHX_ const char *src, size_t len)
{
    char *dest;

    Newx(dest, len + 1, char);

    if (dest == NULL) {
        return NULL;
    }

    memcpy(dest, src, len);
    dest[len] = '\0';
    return dest;
}

#include "net_quic_tls.h"

static void
net_quic_endpoint_free(pTHX_ net_quic_endpoint *ep)
{
    if (ep == NULL) {
        return;
    }

    if (ep->conn != NULL) {
        ngtcp2_conn_del(ep->conn);
        ep->conn = NULL;
    }

    net_quic_tls_cleanup(aTHX_ ep);

    Safefree(ep->alpn);
    Safefree(ep->server_name);
    Safefree(ep);
}

static net_quic_endpoint *
net_quic_endpoint_from_sv(SV *self)
{
    net_quic_endpoint *ep;

    if (!SvROK(self) || !sv_derived_from(self, "Net::QUIC::Endpoint")) {
        croak("not a Net::QUIC::Endpoint object");
    }

    ep = INT2PTR(net_quic_endpoint *, SvIV(SvRV(self)));
    if (ep == NULL) {
        croak("Net::QUIC::Endpoint has already been destroyed");
    }

    return ep;
}

static SV *
net_quic_endpoint_bless(const char *class, net_quic_endpoint *ep)
{
    SV *inner = newSViv(PTR2IV(ep));
    SV *rv = newRV_noinc(inner);
    sv_bless(rv, gv_stashpv(class, GV_ADD));
    return rv;
}

static SV *
net_quic_datagram_new(
    const uint8_t *data,
    size_t datalen,
    const ngtcp2_addr *local,
    const ngtcp2_addr *peer
)
{
    AV *av = newAV();
    SV *rv;

    av_push(av, newSVpvn((const char *)data, (STRLEN)datalen));
    av_push(av, newSVpvn((const char *)local->addr, (STRLEN)local->addrlen));
    av_push(av, newSVpvn((const char *)peer->addr, (STRLEN)peer->addrlen));

    rv = newRV_noinc((SV *)av);
    sv_bless(rv, gv_stashpv("Net::QUIC::Datagram", GV_ADD));
    return rv;
}

