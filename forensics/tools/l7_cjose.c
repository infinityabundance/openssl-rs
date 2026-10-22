/* cjose JWS HS256 harness: sign, import, verify, and reject tampered/wrong-key inputs. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <cjose/cjose.h>

int main(int argc, char **argv) {
    (void) argv;
    if (argc > 1) { printf("cjose-l7-harness\n"); return 0; }
    static const unsigned char key[] = "phase25-l7-cjose-hmac-key-0123456789";
    static const unsigned char wrong[] = "phase25-l7-cjose-wrong-key-9876543210";
    static const unsigned char payload[] = "phase25-l7-cjose-payload";
    cjose_err err;
    memset(&err, 0, sizeof(err));
    cjose_jwk_t *jwk = cjose_jwk_create_oct_spec(key, sizeof(key) - 1, &err);
    cjose_jwk_t *bad = cjose_jwk_create_oct_spec(wrong, sizeof(wrong) - 1, &err);
    cjose_header_t *hdr = cjose_header_new(&err);
    if (!jwk || !bad || !hdr) { printf("sign=failed key\n"); return 3; }
    if (!cjose_header_set(hdr, "alg", "HS256", &err)) { printf("sign=failed header\n"); return 3; }
    cjose_jws_t *jws = cjose_jws_sign(jwk, hdr, payload, sizeof(payload) - 1, &err);
    if (!jws) { printf("sign=failed %s\n", err.message ? err.message : ""); return 0; }
    const char *compact = NULL;
    if (!cjose_jws_export(jws, &compact, &err) || !compact) { printf("export=failed\n"); cjose_jws_release(jws); return 0; }
    char buf[1024];
    snprintf(buf, sizeof(buf), "%s", compact);
    cjose_jws_t *imported = cjose_jws_import(buf, strlen(buf), &err);
    int verified = imported && cjose_jws_verify(imported, jwk, &err);
    int wrongkey = imported && cjose_jws_verify(imported, bad, &err) ? 1 : 0;
    char tampered[1024];
    snprintf(tampered, sizeof(tampered), "%s", buf);
    size_t len = strlen(tampered);
    if (len > 8) tampered[len - 3] = (tampered[len - 3] == 65) ? 66 : 65;
    cjose_jws_t *tjws = cjose_jws_import(tampered, strlen(tampered), &err);
    int tamper_ok = tjws && cjose_jws_verify(tjws, jwk, &err) ? 1 : 0;
    printf("sign=ok import=%s verify=%s tamper=%s wrongkey=%s\n",
           imported ? "ok" : "failed", verified ? "ok" : "failed",
           tamper_ok ? "accepted" : "rejected", wrongkey ? "accepted" : "rejected");
    if (tjws) cjose_jws_release(tjws);
    if (imported) cjose_jws_release(imported);
    cjose_jws_release(jws);
    cjose_header_release(hdr);
    cjose_jwk_release(jwk);
    cjose_jwk_release(bad);
    return 0;
}
