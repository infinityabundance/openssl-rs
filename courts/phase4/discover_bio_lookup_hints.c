/*
 * openssl-rs — discovery probe 4: what resolver inputs and post-processing does
 * BIO_lookup_ex use? Entry count, order and per-entry protocol are observable, so
 * the hints have to be identified rather than guessed.
 *
 * For each case this prints the entry count from BIO_lookup_ex AND from getaddrinfo
 * called directly with several candidate hint sets, so the one the authority uses
 * can be recognised by agreement.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#include <openssl/bio.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>

/* Count the entries getaddrinfo returns for a hint set. */
static int gai_count(const char *host, const char *service, int family, int socktype,
                     int protocol, int flags)
{
    struct addrinfo hints, *res = NULL, *it;
    int n = 0, r;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = family;
    hints.ai_socktype = socktype;
    hints.ai_protocol = protocol;
    hints.ai_flags = flags;
    r = getaddrinfo(host, service, &hints, &res);
    if (r != 0) {
        if (res != NULL)
            freeaddrinfo(res);
        return -1000 + r; /* encode the EAI error so it is visible */
    }
    for (it = res; it != NULL; it = it->ai_next)
        n++;
    freeaddrinfo(res);
    return n;
}

static void case_lookup(const char *key, const char *host, const char *service,
                        int lookup_type, int family, int socktype, int protocol)
{
    BIO_ADDRINFO *res = NULL;
    const BIO_ADDRINFO *it;
    int n = 0, r;

    ERR_clear_error();
    r = BIO_lookup_ex(host, service, lookup_type, family, socktype, protocol, &res);
    printf("%s.bio.ret=%d\n", key, r);
    for (it = res; it != NULL && n < 8; it = BIO_ADDRINFO_next(it))
        n++;
    printf("%s.bio.count=%d\n", key, n);
    if (res != NULL) {
        const BIO_ADDR *ad = BIO_ADDRINFO_address(res);
        char *s = ad ? BIO_ADDR_hostname_string(ad, 1) : NULL;
        printf("%s.bio.first.host=%s\n", key, s ? s : "<NULL>");
        OPENSSL_free(s);
        s = ad ? BIO_ADDR_service_string(ad, 1) : NULL;
        printf("%s.bio.first.serv=%s\n", key, s ? s : "<NULL>");
        OPENSSL_free(s);
        printf("%s.bio.first.family=%d\n", key, BIO_ADDRINFO_family(res));
        printf("%s.bio.first.socktype=%d\n", key, BIO_ADDRINFO_socktype(res));
        printf("%s.bio.first.protocol=%d\n", key, BIO_ADDRINFO_protocol(res));
    }
    printf("%s.err.after=%lu\n", key, ERR_peek_error());
    if (ERR_peek_error() != 0) {
        char ebuf[256];
        ERR_error_string_n(ERR_peek_error(), ebuf, sizeof(ebuf));
        printf("%s.err.string=%s\n", key, ebuf);
        printf("%s.err.reason=%s\n", key,
               ERR_reason_error_string(ERR_peek_error()) == NULL
                   ? "<NULL>" : ERR_reason_error_string(ERR_peek_error()));
    }
    printf("%s.res.isnull=%d\n", key, res == NULL);
    BIO_ADDRINFO_free(res);

    /* The candidate hint sets, with AI_ADDRCONFIG as the authority's base. */
    printf("%s.gai.addrconfig=%d\n", key,
           gai_count(host, service, family, socktype, protocol, AI_ADDRCONFIG));
    printf("%s.gai.addrconfig.passive=%d\n", key,
           gai_count(host, service, family, socktype, protocol,
                     AI_ADDRCONFIG | AI_PASSIVE));
    printf("%s.gai.none=%d\n", key, gai_count(host, service, family, socktype, protocol, 0));
    printf("%s.gai.passive=%d\n", key,
           gai_count(host, service, family, socktype, protocol, AI_PASSIVE));
    printf("%s.gai.addrconfig.canonname=%d\n", key,
           gai_count(host, service, family, socktype, protocol,
                     AI_ADDRCONFIG | AI_CANONNAME));
}

int main(void)
{
    setvbuf(stdout, NULL, _IONBF, 0);

    /* The case that showed two entries. */
    case_lookup("c1", "localhost", "80", BIO_LOOKUP_CLIENT, AF_INET, SOCK_STREAM, 0);
    case_lookup("c2", "localhost", "80", BIO_LOOKUP_CLIENT, AF_INET, SOCK_STREAM,
                IPPROTO_TCP);
    /* A numeric host, where the resolver has nothing to look up. */
    case_lookup("c3", "127.0.0.1", "8080", BIO_LOOKUP_CLIENT, AF_INET, SOCK_STREAM, 0);
    /* Datagram, and socktype 0 (which the caller may pass). */
    case_lookup("c4", "localhost", "80", BIO_LOOKUP_CLIENT, AF_INET, SOCK_DGRAM, 0);
    case_lookup("c5", "localhost", "80", BIO_LOOKUP_CLIENT, AF_INET, 0, 0);
    /* The server side, which is where AI_PASSIVE would show up. */
    case_lookup("c6", NULL, "80", BIO_LOOKUP_SERVER, AF_INET, SOCK_STREAM, 0);
    case_lookup("c7", "localhost", "80", BIO_LOOKUP_SERVER, AF_INET, SOCK_STREAM, 0);
    case_lookup("c8", NULL, "80", BIO_LOOKUP_SERVER, AF_INET6, SOCK_STREAM, 0);
    /* A missing service. */
    case_lookup("c9", "localhost", NULL, BIO_LOOKUP_CLIENT, AF_INET, SOCK_STREAM, 0);
    /* An unknown host: what does it leave behind? */
    case_lookup("c10", "no-such-host.invalid", "80", BIO_LOOKUP_CLIENT, AF_INET,
                SOCK_STREAM, 0);
    /* A bad service name. */
    case_lookup("c11", "localhost", "no-such-service-xyz", BIO_LOOKUP_CLIENT, AF_INET,
                SOCK_STREAM, 0);
    /* A mismatched protocol, and a bogus one. */
    case_lookup("c12", "localhost", "80", BIO_LOOKUP_CLIENT, AF_INET, SOCK_STREAM,
                IPPROTO_UDP);
    case_lookup("c13", "localhost", "80", BIO_LOOKUP_CLIENT, AF_INET, SOCK_STREAM, 999);
    /* AF_UNSPEC, which may yield both families. */
    case_lookup("c14", "localhost", "80", BIO_LOOKUP_CLIENT, AF_UNSPEC, SOCK_STREAM, 0);
    /* An empty host string rather than NULL. */
    case_lookup("c15", "", "80", BIO_LOOKUP_CLIENT, AF_INET, SOCK_STREAM, 0);

    return 0;
}
