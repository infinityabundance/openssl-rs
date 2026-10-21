/*
 * Phase-25 L7 workload for the library-only `libtins` family.
 *
 * libtins ships no program of its own. This harness exercises its OpenSSL
 * crypto backend: the WPA2 supplicant PMK derivation (PBKDF2-HMAC-SHA1 over
 * the passphrase and SSID) must reproduce the IEEE 802.11i test vector, and a
 * corrupted passphrase must derive a different key.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#include <tins/config.h>

#if !defined(TINS_HAVE_WPA2_DECRYPTION)
#error "this harness requires libtins built with WPA2 decryption (OpenSSL)"
#endif

#include <tins/crypto.h>

#include <cstdio>
#include <cstring>
#include <string>

static std::string hex(const std::vector<uint8_t> &key)
{
    static const char digits[] = "0123456789abcdef";
    std::string out;
    for (uint8_t b : key) {
        out.push_back(digits[b >> 4]);
        out.push_back(digits[b & 0x0f]);
    }
    return out;
}

int main(int argc, char **argv)
{
    if (argc > 1 && std::strcmp(argv[1], "--version") == 0) {
        std::printf("libtins-l7-harness\n");
        return 0;
    }

    /* IEEE 802.11i test vector: PMK = PBKDF2(HMAC-SHA1, "password", "IEEE", 4096, 32). */
    const std::string expected =
        "f42c6fc52df0ebef9ebb4b90b38a5f90"
        "2e83fe1b135a70e23aed762e9710a12e";

    Tins::Crypto::WPA2::SupplicantData good("password", "IEEE");
    std::string pmk = hex(good.pmk());
    std::printf("pmk=%s\n", pmk.c_str());
    if (pmk != expected) {
        std::fprintf(stderr, "libtins: PMK %s does not match the 802.11i vector %s\n",
                     pmk.c_str(), expected.c_str());
        return 1;
    }
    std::printf("pmk_vector=ok\n");

    Tins::Crypto::WPA2::SupplicantData corrupt("passw0rd", "IEEE");
    std::string other = hex(corrupt.pmk());
    if (other == expected || other.size() != expected.size()) {
        std::fprintf(stderr, "libtins: the corrupted passphrase derived the vector PMK\n");
        return 1;
    }
    std::printf("corrupt_input_differs=ok\n");
    return 0;
}
