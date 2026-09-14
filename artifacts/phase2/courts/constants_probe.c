
#include <stdio.h>
#include <openssl/aes.h>
#include <openssl/evp.h>
#include <openssl/md5.h>
#include <openssl/objects.h>
#include <openssl/opensslv.h>
#include <openssl/sha.h>
#include <openssl/ssl.h>
#include <openssl/x509_vfy.h>

#define P(x) printf("%s\t%lld\n", #x, (long long)(x))

int main(void) {
    P(OPENSSL_VERSION_NUMBER);
    P(OPENSSL_VERSION_MAJOR); P(OPENSSL_VERSION_MINOR); P(OPENSSL_VERSION_PATCH);
    P(EVP_MAX_MD_SIZE); P(EVP_MAX_KEY_LENGTH); P(EVP_MAX_IV_LENGTH);
    P(EVP_MAX_BLOCK_LENGTH);
    P(SHA256_DIGEST_LENGTH); P(SHA512_DIGEST_LENGTH); P(MD5_DIGEST_LENGTH);
    P(AES_BLOCK_SIZE);
    P(TLS1_2_VERSION); P(TLS1_3_VERSION); P(DTLS1_2_VERSION);
    P(X509_V_OK); P(X509_V_ERR_CERT_HAS_EXPIRED);
    P(NID_sha256); P(NID_sha512); P(NID_X9_62_prime256v1);
    P(EVP_PKEY_RSA); P(EVP_PKEY_EC); P(EVP_PKEY_ED25519); P(EVP_PKEY_X25519);
    P(SSL_VERIFY_NONE); P(SSL_VERIFY_PEER); P(SSL_VERIFY_FAIL_IF_NO_PEER_CERT);
    return 0;
}
