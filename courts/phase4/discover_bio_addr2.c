/*
 * openssl-rs — discovery probe 2: two specific BIO_ADDR/BIO_lookup behaviours.
 *
 * 1. BIO_ADDR_service_string() reports a byte-swapped port for 8080 (36895). Pin
 *    down the model: is the port stored in the temporary sockaddr without htons?
 * 2. BIO_lookup("localhost", "http", ...) returned 0 while port "80" worked. Find
 *    out whether that is OpenSSL's doing or glibc's, by calling getaddrinfo with
 *    the same hints directly.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#include <openssl/bio.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>

static void show_service(const char *label, unsigned short port, int numeric)
{
    BIO_ADDR *a = BIO_ADDR_new();
    struct in_addr in;
    char *s;

    inet_pton(AF_INET, "127.0.0.1", &in);
    BIO_ADDR_rawmake(a, AF_INET, &in, sizeof(in), port);
    s = BIO_ADDR_service_string(a, numeric);
    printf("%s.port=%u numeric=%d rawport=%u service=%s\n", label, (unsigned)port,
           numeric, (unsigned)BIO_ADDR_rawport(a), s == NULL ? "<NULL>" : s);
    OPENSSL_free(s);
    BIO_ADDR_free(a);
}

int main(void)
{
    struct addrinfo hints, *res = NULL;
    int r;

    setvbuf(stdout, NULL, _IONBF, 0);

    show_service("svc80", 80, 1);
    show_service("svc80named", 80, 0);
    show_service("svc443", 443, 1);
    show_service("svc0", 0, 1);
    show_service("svc65535", 65535, 1);
    show_service("svc1", 1, 1);
    show_service("svc20", 20, 0);   /* ftp-data: a name that exists in /etc/services */

    /* Direct glibc comparison for BIO_lookup's service-name path. */
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = 0;
    hints.ai_flags = AI_ADDRCONFIG;
    r = getaddrinfo("localhost", "http", &hints, &res);
    printf("gai.http.sockstream.proto0=%d\n", r);
    if (r == 0)
        freeaddrinfo(res);

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = 6; /* IPPROTO_TCP */
    hints.ai_flags = AI_ADDRCONFIG;
    r = getaddrinfo("localhost", "http", &hints, &res);
    printf("gai.http.sockstream.prototcp=%d\n", r);
    if (r == 0)
        freeaddrinfo(res);

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = 0;
    hints.ai_protocol = 0;
    hints.ai_flags = AI_ADDRCONFIG;
    r = getaddrinfo("localhost", "http", &hints, &res);
    printf("gai.http.sock0=%d\n", r);
    if (r == 0)
        freeaddrinfo(res);

    /* And the same two through OpenSSL, for the record. */
    {
        BIO_ADDRINFO *ai = NULL;
        r = BIO_lookup("localhost", "http", BIO_LOOKUP_CLIENT, AF_INET, 0, &ai);
        printf("bio.lookup.http.sock0=%d\n", r);
        BIO_ADDRINFO_free(ai);
        ai = NULL;
        r = BIO_lookup("localhost", "80", BIO_LOOKUP_CLIENT, AF_INET, 0, &ai);
        printf("bio.lookup.80.sock0=%d\n", r);
        BIO_ADDRINFO_free(ai);
        ai = NULL;
        r = BIO_lookup_ex("localhost", "http", BIO_LOOKUP_CLIENT, AF_INET,
                          SOCK_STREAM, 0, &ai);
        printf("bio.lookup_ex.http.protocol0=%d\n", r);
        BIO_ADDRINFO_free(ai);
        ai = NULL;
        r = BIO_lookup_ex("localhost", "http", BIO_LOOKUP_CLIENT, AF_INET,
                          SOCK_STREAM, IPPROTO_TCP, &ai);
        printf("bio.lookup_ex.http.tcp=%d\n", r);
        BIO_ADDRINFO_free(ai);
    }

    return 0;
}
