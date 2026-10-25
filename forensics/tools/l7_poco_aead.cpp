/*
 * S65 typed library-harness example: Poco's AES-256-GCM consumer path.
 *
 * The family (`poco`) ships no executable, so this harness is the workload
 * program.  It calls only Poco's public API -- it includes no OpenSSL header
 * and references no OpenSSL symbol -- while `libPocoCrypto` performs the
 * EVP/AES-GCM operations through the subject libcrypto.  The template layer's
 * consumer gate proves that split at the ELF level:
 *
 *   - this harness imports zero OpenSSL symbols, and references a symbol that
 *     libPocoCrypto exports;
 *   - libPocoCrypto imports OpenSSL symbols.
 *
 * Shape: initialisation (OpenSSLInitializer), context construction
 * (CipherFactory/CipherKey), input processing (transform), output validation
 * (decrypt + compare), cleanup (RAII/AutoPtr), and an error-handling case
 * (`--tamper`: a modified GCM tag must be rejected).
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <Poco/AutoPtr.h>
#include <Poco/Crypto/Cipher.h>
#include <Poco/Crypto/CipherFactory.h>
#include <Poco/Crypto/CipherKey.h>
#include <Poco/Crypto/CryptoTransform.h>
#include <Poco/Crypto/OpenSSLInitializer.h>
#include <Poco/Exception.h>

#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

namespace {

const char kPayload[] = "s65-poco-aead-roundtrip-payload";

int run(bool tamper) {
    std::vector<unsigned char> key(32, 0x11);
    std::vector<unsigned char> iv(12, 0x22);
    const std::string payload(kPayload);

    Poco::Crypto::OpenSSLInitializer initializer;  // initialisation
    Poco::Crypto::CipherFactory& factory = Poco::Crypto::CipherFactory::defaultFactory();
    Poco::AutoPtr<Poco::Crypto::Cipher> cipher(
        factory.createCipher(Poco::Crypto::CipherKey("aes-256-gcm", key, iv)));

    // context construction + input processing
    Poco::Crypto::CryptoTransform::Ptr encryptor = cipher->createEncryptor();
    std::string ciphertext(payload.size() + 32, '\0');
    std::streamsize written = encryptor->transform(
        reinterpret_cast<const unsigned char*>(payload.data()),
        static_cast<std::streamsize>(payload.size()),
        reinterpret_cast<unsigned char*>(&ciphertext[0]),
        static_cast<std::streamsize>(ciphertext.size()));
    written += encryptor->finalize(
        reinterpret_cast<unsigned char*>(&ciphertext[0]) + written,
        static_cast<std::streamsize>(ciphertext.size()) - written);
    ciphertext.resize(static_cast<std::size_t>(written));

    std::string tag = encryptor->getTag(16);
    if (tamper) {
        tag[0] = static_cast<char>(tag[0] ^ 0x01);
    }

    // output validation: decrypt with the tag and compare to the input
    Poco::Crypto::CryptoTransform::Ptr decryptor = cipher->createDecryptor();
    decryptor->setTag(tag);
    std::string plaintext(ciphertext.size() + 32, '\0');
    std::streamsize produced = decryptor->transform(
        reinterpret_cast<const unsigned char*>(ciphertext.data()),
        static_cast<std::streamsize>(ciphertext.size()),
        reinterpret_cast<unsigned char*>(&plaintext[0]),
        static_cast<std::streamsize>(plaintext.size()));
    bool ok = false;
    try {
        produced += decryptor->finalize(
            reinterpret_cast<unsigned char*>(&plaintext[0]) + produced,
            static_cast<std::streamsize>(plaintext.size()) - produced);
        plaintext.resize(static_cast<std::size_t>(produced));
        ok = (plaintext == payload);
    } catch (const Poco::Exception&) {
        ok = false;
    }

    if (tamper) {
        std::printf("aead_tamper=%s\n", ok ? "accepted" : "rejected");
        return ok ? 3 : 0;
    }
    std::printf("aead_roundtrip=%s\n", ok ? "ok" : "fail");
    return ok ? 0 : 2;
}

}  // namespace

int main(int argc, char** argv) {
    if (argc > 1 && std::strcmp(argv[1], "--version") == 0) {
        std::printf("poco-aead-harness\n");
        return 0;
    }
    const bool tamper = (argc > 1 && std::strcmp(argv[1], "--tamper") == 0);
    try {
        return run(tamper);
    } catch (const Poco::Exception& exc) {
        std::printf("aead_error=%s\n", exc.displayText().c_str());
        return 1;
    }
}
