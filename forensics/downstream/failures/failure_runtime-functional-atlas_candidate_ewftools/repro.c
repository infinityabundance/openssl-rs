/* minimized reproducer -- standalone, deterministic, one OpenSSL call */
#include <stdio.h>
#include <openssl/opensslv.h>
int main(void) {
    printf("OPENSSL_VERSION_NUMBER=%lu\n", (unsigned long) OPENSSL_VERSION_NUMBER);
    return 0;
}
