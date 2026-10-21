/*
 * l7_opendkim.c -- the admitted L7 workload for the opendkim downstream family.
 *
 * opendkim ships its DKIM engine as libopendkim, and the filter executable is a
 * milter client: driving it end-to-end needs a sendmail milter peer, which this
 * venue does not admit. The library's own sign/verify path is therefore the
 * admitted consumer. This harness links the libopendkim built from the pristine
 * opendkim source in the same tree (and the subject libcrypto it was linked
 * against), signs a message, verifies the signature, and reports a result the
 * runtime recipe asserts on.
 *
 * Modes:
 *   sign   <message> <private-key> <domain> <selector> <out-signed>
 *   verify <signed-message> <public-key-record>
 *
 * `public-key-record` is a DKIM DNS TXT record value:
 *   v=DKIM1; k=rsa; p=<base64 SubjectPublicKeyInfo>
 *
 * Exit: 0 on the requested operation's success, 1 on failure, 2 on usage.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <dkim.h>

#define MAX_MSG (1 << 20)

static char *g_pubkey;

static DKIM_CBSTAT key_lookup(DKIM *dkim, DKIM_SIGINFO *sig, u_char *buf, size_t buflen)
{
	const char *selector;
	const char *domain;
	size_t n;

	(void) dkim;

	if (g_pubkey == NULL)
		return DKIM_CBSTAT_ERROR;

	selector = (const char *) dkim_sig_getselector(sig);
	domain = (const char *) dkim_sig_getdomain(sig);
	if (selector == NULL || domain == NULL)
		return DKIM_CBSTAT_ERROR;

	/*
	 * The venue's lookup answers the one key it was given; a signature that
	 * names a different selector or domain is a real mismatch, not a lookup
	 * failure, so it is reported as not found.
	 */
	if (strcmp(selector, "l7sel") != 0 || strcmp(domain, "example.test") != 0)
		return DKIM_CBSTAT_ERROR;

	n = strlen(g_pubkey);
	if (n + 1 > buflen)
		return DKIM_CBSTAT_ERROR;

	memset(buf, 0, buflen);
	memcpy(buf, g_pubkey, n);
	return DKIM_CBSTAT_CONTINUE;
}

static unsigned char *read_file(const char *path, size_t *lenp)
{
	FILE *f;
	unsigned char *buf;
	long size;
	size_t got;

	f = fopen(path, "rb");
	if (f == NULL) {
		fprintf(stderr, "open %s: %s\n", path, strerror(errno));
		return NULL;
	}
	if (fseek(f, 0, SEEK_END) != 0) {
		fclose(f);
		return NULL;
	}
	size = ftell(f);
	if (size < 0 || size > MAX_MSG) {
		fclose(f);
		return NULL;
	}
	rewind(f);
	buf = malloc((size_t) size + 1);
	if (buf == NULL) {
		fclose(f);
		return NULL;
	}
	got = fread(buf, 1, (size_t) size, f);
	fclose(f);
	if (got != (size_t) size) {
		free(buf);
		return NULL;
	}
	buf[got] = '\0';
	*lenp = got;
	return buf;
}

/*
 * Normalise the message to CRLF line endings, exactly as the signing and
 * verification passes must see the same bytes. Returns a malloc'd buffer.
 */
static unsigned char *to_crlf(const unsigned char *in, size_t len, size_t *outlen)
{
	unsigned char *out;
	size_t i, o = 0;

	out = malloc(len * 2 + 2);
	if (out == NULL)
		return NULL;
	for (i = 0; i < len; i++) {
		if (in[i] == '\r') {
			if (i + 1 < len && in[i + 1] == '\n')
				continue;
			out[o++] = '\r';
			out[o++] = '\n';
		} else if (in[i] == '\n') {
			out[o++] = '\r';
			out[o++] = '\n';
		} else {
			out[o++] = in[i];
		}
	}
	if (o < 2 || out[o - 2] != '\r' || out[o - 1] != '\n') {
		out[o++] = '\r';
		out[o++] = '\n';
	}
	*outlen = o;
	return out;
}

/*
 * Feed a CRLF message to a DKIM handle: folded header fields to dkim_header,
 * then the body. Returns 0 on success.
 */
static int feed(DKIM *dkim, const unsigned char *msg, size_t len)
{
	size_t i, hdr_end, hdr_start;
	DKIM_STAT st;

	/* Locate the blank line separating headers from body. */
	hdr_end = 0;
	for (i = 0; i + 3 < len; i++) {
		if (msg[i] == '\r' && msg[i + 1] == '\n' &&
		    msg[i + 2] == '\r' && msg[i + 3] == '\n') {
			hdr_end = i;
			break;
		}
	}
	if (hdr_end == 0 && len >= 2 && msg[0] == '\r' && msg[1] == '\n')
		hdr_end = 0;

	/*
	 * Each header field is one CRLF-terminated buffer; a line beginning with
	 * space or tab continues the previous field, so the field ends at the
	 * first CRLF that is followed by a non-continuation line (or by the
	 * blank line that ends the block).
	 */
	hdr_start = 0;
	i = 0;
	while (hdr_end > 0 && i < hdr_end) {
		if (msg[i] == '\r' && msg[i + 1] == '\n') {
			size_t next = i + 2;
			int continuation = (next < hdr_end &&
			                    (msg[next] == ' ' || msg[next] == '\t'));
			if (!continuation) {
				st = dkim_header(dkim, (u_char *) msg + hdr_start,
				                 next - hdr_start);
				if (st != DKIM_STAT_OK) {
					fprintf(stderr, "dkim_header: %s\n",
					        dkim_getresultstr(st));
					return -1;
				}
				hdr_start = next;
			}
			i = next;
			continue;
		}
		i++;
	}
	if (hdr_end > 0 && hdr_start < hdr_end) {
		st = dkim_header(dkim, (u_char *) msg + hdr_start, hdr_end - hdr_start);
		if (st != DKIM_STAT_OK) {
			fprintf(stderr, "dkim_header: %s\n", dkim_getresultstr(st));
			return -1;
		}
	}

	st = dkim_eoh(dkim);
	if (st != DKIM_STAT_OK) {
		fprintf(stderr, "dkim_eoh: %s\n", dkim_getresultstr(st));
		return -1;
	}

	if (hdr_end + 4 <= len) {
		st = dkim_body(dkim, (u_char *) msg + hdr_end + 4, len - (hdr_end + 4));
		if (st != DKIM_STAT_OK) {
			fprintf(stderr, "dkim_body: %s\n", dkim_getresultstr(st));
			return -1;
		}
	}

	st = dkim_eom(dkim, NULL);
	if (st != DKIM_STAT_OK) {
		fprintf(stderr, "dkim_eom: %s\n", dkim_getresultstr(st));
		return -1;
	}
	return 0;
}

static int do_sign(const char *msg_path, const char *key_path, const char *domain,
                   const char *selector, const char *out_path)
{
	unsigned char *raw = NULL, *msg = NULL, *key = NULL;
	size_t rawlen = 0, msglen = 0, keylen = 0;
	unsigned char sighdr[8192];
	size_t slen;
	DKIM_LIB *lib = NULL;
	DKIM *dkim = NULL;
	DKIM_STAT st;
	FILE *out = NULL;
	int rc = 1;

	raw = read_file(msg_path, &rawlen);
	key = read_file(key_path, &keylen);
	if (raw == NULL || key == NULL)
		goto out;
	msg = to_crlf(raw, rawlen, &msglen);
	if (msg == NULL)
		goto out;

	lib = dkim_init(NULL, NULL);
	if (lib == NULL) {
		fprintf(stderr, "dkim_init failed\n");
		goto out;
	}
	dkim = dkim_sign(lib, (const unsigned char *) "l7-opendkim",
	                 NULL, (const dkim_sigkey_t) key,
	                 (const unsigned char *) selector,
	                 (const unsigned char *) domain,
	                 DKIM_CANON_RELAXED, DKIM_CANON_RELAXED,
	                 DKIM_SIGN_RSASHA256, -1, &st);
	if (dkim == NULL) {
		fprintf(stderr, "dkim_sign: %s\n", dkim_getresultstr(st));
		goto out;
	}
	if (feed(dkim, msg, msglen) != 0)
		goto out;

	memset(sighdr, 0, sizeof sighdr);
	st = dkim_getsighdr(dkim, sighdr, sizeof sighdr - 1, 0);
	if (st != DKIM_STAT_OK) {
		fprintf(stderr, "dkim_getsighdr: %s\n", dkim_getresultstr(st));
		goto out;
	}

	out = fopen(out_path, "wb");
	if (out == NULL) {
		fprintf(stderr, "open %s: %s\n", out_path, strerror(errno));
		goto out;
	}
	slen = strlen((char *) sighdr);
	if (fwrite("DKIM-Signature: ", 1, 16, out) != 16 ||
	    fwrite(sighdr, 1, slen, out) != slen) {
		fprintf(stderr, "write %s failed\n", out_path);
		goto out;
	}
	if (slen < 2 || sighdr[slen - 2] != '\r' || sighdr[slen - 1] != '\n') {
		if (fwrite("\r\n", 1, 2, out) != 2) {
			fprintf(stderr, "write %s failed\n", out_path);
			goto out;
		}
	}
	if (fwrite(msg, 1, msglen, out) != msglen) {
		fprintf(stderr, "write %s failed\n", out_path);
		goto out;
	}
	rc = 0;
out:
	if (out != NULL)
		fclose(out);
	if (dkim != NULL)
		dkim_free(dkim);
	if (lib != NULL)
		dkim_close(lib);
	free(raw);
	free(key);
	free(msg);
	return rc;
}

static int do_verify(const char *msg_path, const char *key_path)
{
	unsigned char *raw = NULL, *msg = NULL, *key = NULL;
	size_t rawlen = 0, msglen = 0, keylen = 0;
	DKIM_LIB *lib = NULL;
	DKIM *dkim = NULL;
	DKIM_SIGINFO *sig;
	DKIM_STAT st;
	int rc = 1;

	raw = read_file(msg_path, &rawlen);
	key = read_file(key_path, &keylen);
	if (raw == NULL || key == NULL)
		goto out;
	key[keylen] = '\0';
	g_pubkey = (char *) key;
	msg = to_crlf(raw, rawlen, &msglen);
	if (msg == NULL)
		goto out;

	lib = dkim_init(NULL, NULL);
	if (lib == NULL) {
		fprintf(stderr, "dkim_init failed\n");
		goto out;
	}
	dkim_set_key_lookup(lib, key_lookup);
	dkim = dkim_verify(lib, (const unsigned char *) "l7-opendkim", NULL, &st);
	if (dkim == NULL) {
		fprintf(stderr, "dkim_verify: %s\n", dkim_getresultstr(st));
		goto out;
	}
	if (feed(dkim, msg, msglen) != 0)
		goto out;

	sig = dkim_getsignature(dkim);
	if (sig == NULL) {
		printf("verify=fail: no signature\n");
		goto out;
	}
	/*
	 * Spelled out rather than using dkim.h's DKIM_SIG_CHECK macro: that macro
	 * lacks parentheses around its flags test, so it tests bit 0 instead of
	 * DKIM_SIGFLAG_PASSED.
	 */
	if ((dkim_sig_getflags(sig) & DKIM_SIGFLAG_PASSED) == 0 ||
	    dkim_sig_getbh(sig) != DKIM_SIGBH_MATCH) {
		printf("verify=fail: %s (sig error %d)\n",
		       dkim_sig_geterrorstr(dkim_sig_geterror(sig)),
		       dkim_sig_geterror(sig));
		goto out;
	}
	printf("verify=ok\n");
	rc = 0;
out:
	if (dkim != NULL)
		dkim_free(dkim);
	if (lib != NULL)
		dkim_close(lib);
	free(raw);
	free(key);
	free(msg);
	return rc;
}

int main(int argc, char **argv)
{
	if (argc == 2 && strcmp(argv[1], "--version") == 0) {
		printf("opendkim-l7-harness\n");
		return 0;
	}
	if (argc == 7 && strcmp(argv[1], "sign") == 0)
		return do_sign(argv[2], argv[3], argv[4], argv[5], argv[6]) == 0 ? 0 : 1;
	if (argc == 4 && strcmp(argv[1], "verify") == 0)
		return do_verify(argv[2], argv[3]) == 0 ? 0 : 1;

	fprintf(stderr, "usage: %s sign <msg> <key> <domain> <selector> <out>\n"
	                "       %s verify <msg> <key-record>\n", argv[0], argv[0]);
	return 2;
}
