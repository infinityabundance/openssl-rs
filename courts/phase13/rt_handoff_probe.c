/*
 * rt_handoff_probe.c -- RT-HANDOFF: the Phase-13.8 received TS_CONF and SRP hand-offs, driven.
 *
 * One C program, compiled once against the admitted authority and once against the candidate
 * distribution shell; the two transcripts are diffed line by line, keyed on `key=value`. Every
 * observation is a small integer or a NUL-terminated string -- never an address, never a clock,
 * never the error queue.
 *
 * ## What this probe drives
 *
 * The three exports 12.5/12.8 withheld and 13.8 transcribes:
 *
 *   * `TS_CONF_set_default_engine` (`crypto/ts/ts_conf.c:180-202`) over a fixed `CONF`:
 *     `"builtin"` is accepted before the registry is touched, and an unknown id is refused
 *     because `ENGINE_by_id` answers NULL on both sides. A name that *is* a registered built-in
 *     (`dynamic`, `rdrand`) is deliberately not used: the authority registers those and this
 *     crate registers none (`src/engine/eng_all.rs`), so their answers would diverge.
 *   * `TS_CONF_set_crypto_device` (`:163-178`) over the same `CONF`: a NULL `device` with a
 *     section that has no `crypto_device` entry installs nothing and succeeds (the documented
 *     decision); a NULL `device` with `crypto_device = builtin` reads and delegates; an explicit
 *     `"builtin"` succeeds; an explicit unknown id is refused.
 *   * `SRP_VBASE_init` (`crypto/srp/srp_vfy.c:394-510`) over a fixed verifier file written to
 *     `/tmp`: the `I` record adds the `8192` group (its decoded `N`/`g` cached on
 *     `vb->gN_cache`), the `V` record adds user `alice` (the group resolved by id), a second `V`
 *     naming an absent group is skipped, and the seed-key `SRP_VBASE_new` path sets
 *     `default_g`/`default_N`. The absent-file, NULL-file, malformed-record (wrong field count)
 *     and undecodable-base64 arms are driven by their `SRP_ERR_*` return codes.
 *
 * ## Arms that are deliberately absent
 *
 * No NULL is handed to `TS_CONF_set_default_engine` (its first `strcmp` dereferences the name)
 * or to an SRP accessor that dereferences the base. The error queue is never read: the SRP
 * `SRP_ERR_*` return codes and the TS integer answers are the coordinates this probe publishes,
 * and both sides are drained with `ERR_clear_error` so a raise cannot leak between arms.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/bio.h>
#include <openssl/bn.h>
#include <openssl/conf.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/srp.h>
#include <openssl/ts.h>

static void out_int(const char *key, long v)
{
    printf("%s=%ld\n", key, v);
}

static void out_str(const char *key, const char *s)
{
    printf("%s=%s\n", key, s == NULL ? "(null)" : s);
}

static void write_fixture(const char *path, const char *text)
{
    FILE *f = fopen(path, "wb");

    if (f != NULL) {
        fwrite(text, 1, strlen(text), f);
        fclose(f);
    }
}

/* ---------------------------------------------------------------------------------------------
 * The fixed SRP verifier files. Fields are tab separated and every record has the six columns
 * `crypto/srp/srp_vfy.c` expects (`DB_srptype`, `DB_srpverifier`, `DB_srpsalt`, `DB_srpid`,
 * `DB_srpgN`, `DB_srpinfo`). The base64 is the SRP alphabet, whose strings decode as: `05` ->
 * 0x05, `02` -> 0x02, `0G83` -> 01 02 03, `041GO7` -> 04 05 06 07.
 * ------------------------------------------------------------------------------------------- */

static const char VERIFIER_GOOD[] =
    "# rt-handoff srp verifier fixture\n"
    "I\t05\t02\t8192\tnone\tnone\n"
    "V\t0G83\t041GO7\talice\t8192\tinfo-alice\n"
    "V\t0G83\t041GO7\tbob\tmissing-group\tinfo-bob\n";

/* One record with too few fields: `TXT_DB_read` refuses the whole file. */
static const char VERIFIER_BADFIELDS[] =
    "V\t0G83\n";

/* One `I` record whose `N` field is length 1 mod 4, which `t_fromb64` rejects. */
static const char VERIFIER_BADBN[] =
    "I\t0\t02\tbad\tnone\tnone\n";

#define VERIFIER_GOOD_PATH "/tmp/rt_handoff_verifier.srp"
#define VERIFIER_BADFIELDS_PATH "/tmp/rt_handoff_badfields.srp"
#define VERIFIER_BADBN_PATH "/tmp/rt_handoff_badbn.srp"
#define VERIFIER_ABSENT_PATH "/tmp/rt_handoff_absent.srp"

static void drive_ts(void)
{
    static const char conf_text[] =
        "[tsa]\n"
        "crypto_device = builtin\n"
        "[empty]\n"
        "unused = 1\n";
    BIO *bio = BIO_new_mem_buf(conf_text, -1);
    CONF *conf = NCONF_new(NULL);
    long errline = 0;

    out_int("ts.conf.load", NCONF_load_bio(conf, bio, &errline));
    out_int("ts.conf.errline", errline);
    BIO_free(bio);

    /* A NULL device and a section without the entry: nothing installed, succeeds. */
    out_int("ts.device.null_absent", TS_CONF_set_crypto_device(conf, "empty", NULL));
    /* A NULL device with `crypto_device = builtin`: read from the section and accepted. */
    out_int("ts.device.null_builtin", TS_CONF_set_crypto_device(conf, "tsa", NULL));
    /* An explicit `"builtin"`: accepted before the registry is touched. */
    out_int("ts.device.builtin", TS_CONF_set_crypto_device(conf, "tsa", "builtin"));
    /* An explicit unknown id: `ENGINE_by_id` misses and the reader refuses. */
    ERR_clear_error();
    out_int("ts.device.unknown",
            TS_CONF_set_crypto_device(conf, "tsa", "rt-handoff-no-such-engine"));

    ERR_clear_error();
    out_int("ts.engine.builtin", TS_CONF_set_default_engine("builtin"));
    ERR_clear_error();
    out_int("ts.engine.unknown",
            TS_CONF_set_default_engine("rt-handoff-no-such-engine"));
    ERR_clear_error();

    NCONF_free(conf);
}

static void drive_srp(void)
{
    SRP_VBASE *vb = SRP_VBASE_new(NULL);
    SRP_VBASE *vbs = SRP_VBASE_new("rt-handoff-seed");
    SRP_VBASE *vbn = SRP_VBASE_new(NULL);
    SRP_user_pwd *user;

    write_fixture(VERIFIER_GOOD_PATH, VERIFIER_GOOD);
    write_fixture(VERIFIER_BADFIELDS_PATH, VERIFIER_BADFIELDS);
    write_fixture(VERIFIER_BADBN_PATH, VERIFIER_BADBN);
    remove(VERIFIER_ABSENT_PATH);

    /* ---- a valid file: the I and V records, and the borrowed group ------------------------- */
    out_int("srp.init.ok", SRP_VBASE_init(vb, (char *)VERIFIER_GOOD_PATH));
    out_int("srp.noseed.default_g", vb->default_g != NULL);
    out_int("srp.noseed.default_N", vb->default_N != NULL);

    user = SRP_VBASE_get_by_user(vb, "alice");
    out_int("srp.user.alice", user != NULL);
    if (user != NULL) {
        out_str("srp.user.alice.id", user->id);
        out_str("srp.user.alice.info", user->info);
        out_int("srp.user.alice.v_bits", BN_num_bits(user->v));
        out_int("srp.user.alice.s_bits", BN_num_bits(user->s));
        out_int("srp.user.alice.g_bits", user->g != NULL ? BN_num_bits(user->g) : -1);
        out_int("srp.user.alice.N_bits", user->N != NULL ? BN_num_bits(user->N) : -1);
    }
    out_int("srp.user.bob", SRP_VBASE_get_by_user(vb, "bob") != NULL);
    out_int("srp.user.miss", SRP_VBASE_get_by_user(vb, "nobody") != NULL);

    /* ---- the seed-key path sets the default group ------------------------------------------ */
    out_int("srp.init.seed.ok", SRP_VBASE_init(vbs, (char *)VERIFIER_GOOD_PATH));
    out_int("srp.seed.default_g", vbs->default_g != NULL);
    out_int("srp.seed.default_N", vbs->default_N != NULL);
    out_int("srp.seed.default_g_bits",
            vbs->default_g != NULL ? BN_num_bits(vbs->default_g) : -1);
    out_int("srp.seed.default_N_bits",
            vbs->default_N != NULL ? BN_num_bits(vbs->default_N) : -1);

    /* ---- the refusals, by their SRP_ERR_* codes -------------------------------------------- */
    ERR_clear_error();
    out_int("srp.init.nullfile", SRP_VBASE_init(vbn, NULL));
    ERR_clear_error();
    out_int("srp.init.absent", SRP_VBASE_init(vbn, (char *)VERIFIER_ABSENT_PATH));
    out_int("srp.init.badfields", SRP_VBASE_init(vbn, (char *)VERIFIER_BADFIELDS_PATH));
    out_int("srp.init.badbn", SRP_VBASE_init(vbn, (char *)VERIFIER_BADBN_PATH));
    ERR_clear_error();

    SRP_VBASE_free(vb);
    SRP_VBASE_free(vbs);
    SRP_VBASE_free(vbn);
}

int main(void)
{
    drive_ts();
    drive_srp();
    out_int("done", 1);
    return 0;
}
