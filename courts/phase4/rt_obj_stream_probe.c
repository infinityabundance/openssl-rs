/*
 * openssl-rs — RT-OBJ-STREAM: `OBJ_create_objects`, the description-stream reader.
 *
 * `OBJ_create_objects` reads one object description per line from a BIO and stops
 * at the first line it cannot use — without raising. The interesting part is the
 * *stopping*: a caller feeds it a whole file, so every rejection rule is part of
 * the observable contract, and the count it returns is the only report.
 *
 * The probe feeds it memory BIOs so the input is exact, and after each call asks
 * the object database whether the names landed, which cross-checks the count
 * against `OBJ_sn2nid`/`OBJ_txt2nid` rather than trusting it.
 *
 * One rule that is easy to miss and is exercised deliberately: the reader clears
 * the byte *before* the terminator, so a final line with **no newline** loses its
 * last character. `nl.at.eof` shows `1.3.6.1.4.1.99997.90` becoming a different
 * OID than the one written.
 *
 * All OIDs used are in the private enterprise arc and unique to this probe, so a
 * fresh process always starts from the same database state.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/objects.h>
#include <stdio.h>
#include <string.h>

/* Run `OBJ_create_objects` over a literal stream and report the count. */
static int feed(const char *key, const char *text)
{
    BIO *b = BIO_new_mem_buf(text, (int)strlen(text));
    int n;

    ERR_clear_error();
    n = OBJ_create_objects(b);
    printf("%s.n=%d\n", key, n);
    printf("%s.err0=%lu\n", key, ERR_peek_error());
    ERR_clear_error();
    BIO_free(b);
    return n;
}

static void name_resolves(const char *key, const char *txt)
{
    printf("%s.nid.ge0=%d\n", key, OBJ_txt2nid(txt) > 0);
}

static void err_all(const char *key)
{
    char k[96];
    int n = 0;

    for (;;) {
        const char *file = NULL, *data = NULL;
        int line = 0, flags = 0;
        unsigned long e = ERR_get_error_line_data(&file, &line, &data, &flags);

        if (e == 0)
            break;
        snprintf(k, sizeof(k), "%s.%d.code", key, n);
        printf("%s=%lu\n", k, e);
        snprintf(k, sizeof(k), "%s.%d.line", key, n);
        printf("%s=%d\n", k, line);
        if (++n > 3)
            break;
    }
    snprintf(k, sizeof(k), "%s.count", key);
    printf("%s=%d\n", k, n);
    ERR_clear_error();
}

int main(void)
{
    setvbuf(stdout, NULL, _IONBF, 0);

    /* --- a stream of three well-formed lines ---------------------------- */
    feed("good",
         "1.3.6.1.4.1.99999.1 sha1x long-one\n"
         "1.3.6.1.4.1.99999.2 sha2x long-two\n"
         "1.3.6.1.4.1.99999.3 last-long-name-no-short\n");
    name_resolves("good.1", "1.3.6.1.4.1.99999.1");
    name_resolves("good.2", "1.3.6.1.4.1.99999.2");
    name_resolves("good.3", "1.3.6.1.4.1.99999.3");
    printf("good.sn.ge0=%d\n", OBJ_sn2nid("sha1x") > 0);
    printf("good.ln.ge0=%d\n", OBJ_ln2nid("long-one") > 0);
    printf("good.oid.only.nid.ge0=%d\n", OBJ_sn2nid("last-long-name-no-short") > 0);

    /* --- the count is returned and nothing is raised -------------------- */
    feed("name.collision",
         "1.3.6.1.4.1.99999.4 sha1x reused-long-name\n");

    /* --- a line whose first character is not alphanumeric stops the scan - */
    feed("comment.first",
         "# a comment\n"
         "1.3.6.1.4.1.99999.5 sn5 ln5\n");
    feed("space.first",
         " 1.3.6.1.4.1.99999.6 sn6 ln6\n");

    /* --- a first field that is alphanumeric but has no digits or dots ----- */
    feed("non.numeric.oid", "abc sn ln\n");

    /* --- a line starting with a dot stops at the alphanumeric test ------- */
    feed("dot.first", ".1.2.3 sn ln\n");

    /* --- an empty stream ------------------------------------------------- */
    feed("empty", "");

    /* --- a bare newline stops the scan ----------------------------------- */
    feed("blank.line",
         "\n"
         "1.3.6.1.4.1.99999.7 sn7 ln7\n");

    /* --- only an OID, no names ------------------------------------------- */
    feed("oid.only", "1.3.6.1.4.1.99999.8\n");
    name_resolves("oid.only.nid", "1.3.6.1.4.1.99999.8");

    /* --- no newline on the last line loses its last character ------------ */
    feed("nl.at.eof", "1.3.6.1.4.1.99997.90");
    name_resolves("nl.at.eof.truncated", "1.3.6.1.4.1.99997.9");
    name_resolves("nl.at.eof.as.written", "1.3.6.1.4.1.99997.90");

    /* --- with a newline it survives whole --------------------------------- */
    feed("nl.present", "1.3.6.1.4.1.99997.91\n");
    name_resolves("nl.present.as.written", "1.3.6.1.4.1.99997.91");

    /* --- the stream may be larger than the reader's line buffer ----------- */
    {
        char big[600];
        BIO *b;
        int n;

        memset(big, 'a', sizeof(big) - 1);
        big[sizeof(big) - 1] = '\0';
        b = BIO_new_mem_buf(big, (int)strlen(big));
        ERR_clear_error();
        n = OBJ_create_objects(b);
        printf("long.line.n=%d\n", n);
        printf("long.line.err0=%lu\n", ERR_peek_error());
        ERR_clear_error();
        BIO_free(b);
    }

    /* --- the errors the stream reader cannot reach ------------------------ */
    {
        int nid;

        ERR_clear_error();
        printf("create.allnull=%d\n", OBJ_create(NULL, NULL, NULL));
        err_all("create.allnull");

        ERR_clear_error();
        printf("create.dup.oid=%d\n", OBJ_create("1.3.6.1.4.1.99999.1", NULL, NULL));
        err_all("create.dup.oid");

        ERR_clear_error();
        printf("create.dup.sn=%d\n", OBJ_create("1.3.6.1.4.1.99999.50", "sha1x", NULL));
        err_all("create.dup.sn");

        ERR_clear_error();
        printf("create.dup.ln=%d\n", OBJ_create("1.3.6.1.4.1.99999.51", NULL, "long-one"));
        err_all("create.dup.ln");

        /* A leading letter is rejected with `ASN1_R_FIRST_NUM_TOO_LARGE`, because
         * `OBJ_create` parses through `OBJ_txt2obj(oid, 1)` and hence `a2d`. */
        ERR_clear_error();
        printf("create.bad.oid=%d\n", OBJ_create("not.an.oid", NULL, NULL));
        err_all("create.bad.oid");

        /* Each of `a2d_ASN1_OBJECT`'s rejections, through `OBJ_create`. */
        ERR_clear_error();
        printf("create.oid.first=%d\n", OBJ_create("9.9.9", NULL, NULL));
        err_all("create.oid.first");
        ERR_clear_error();
        printf("create.oid.short=%d\n", OBJ_create("1", NULL, NULL));
        err_all("create.oid.short");
        ERR_clear_error();
        printf("create.oid.sep=%d\n", OBJ_create("1,2", NULL, NULL));
        err_all("create.oid.sep");
        ERR_clear_error();
        printf("create.oid.digit=%d\n", OBJ_create("1.2x.3", NULL, NULL));
        err_all("create.oid.digit");
        ERR_clear_error();
        printf("create.oid.second=%d\n", OBJ_create("0.40.1", NULL, NULL));
        err_all("create.oid.second");
        /* A two-component string that yields no content octets raises nothing. */
        ERR_clear_error();
        printf("create.oid.silent=%d\n", OBJ_create("12", NULL, NULL));
        err_all("create.oid.silent");

        ERR_clear_error();
        nid = OBJ_create("1.3.6.1.4.1.99999.60", "sn60", "ln60");
        printf("create.ok.ge0=%d\n", nid > 0);
        err_all("create.ok");
    }

    /* --- OBJ_txt2obj's own raise, and its silent rejection --------------- */
    {
        ERR_clear_error();
        printf("txt2obj.name.null=%d\n", OBJ_txt2obj("no-such-name", 0) == NULL);
        err_all("txt2obj.name");
        ERR_clear_error();
        printf("txt2obj.numeric.nonnull=%d\n", OBJ_txt2obj("1.3.6.1.4.1.99999.1", 1) != NULL);
        err_all("txt2obj.numeric");
        ERR_clear_error();
        printf("txt2obj.silent.null=%d\n", OBJ_txt2obj("12", 1) == NULL);
        err_all("txt2obj.silent");
        ERR_clear_error();
        printf("txt2obj.malformed.null=%d\n", OBJ_txt2obj("9.9", 1) == NULL);
        err_all("txt2obj.malformed");
    }

    ERR_clear_error();
    printf("err.final=%lu\n", ERR_peek_error());
    ERR_clear_error();
    return 0;
}
