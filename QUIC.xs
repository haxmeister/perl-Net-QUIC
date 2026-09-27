#include "EXTERN.h"
#include "perl.h"
#include "XSUB.h"

#include <string.h>

#include <ngtcp2/ngtcp2.h>
#include <ngtcp2/ngtcp2_crypto.h>

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

MODULE = Net::QUIC    PACKAGE = Net::QUIC

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
