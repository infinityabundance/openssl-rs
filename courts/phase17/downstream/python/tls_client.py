#!/usr/bin/env python3
#
# openssl-rs — Phase 17 downstream: a REAL TLS client using the candidate-linked CPython.
#
# Connects to the authority's `openssl s_server` with a CA-signed cert (SAN IP:127.0.0.1).
# It reports three independent facts:
#   1. the TLS 1.3 handshake completes and the peer certificate is parsed;
#   2. whether the chain is actually verified (an unrelated CA MUST be rejected);
#   3. the buffer-size boundary of the candidate's post-handshake read path.
#
# Exit status is 0 only if verification is enforced (the negative control is rejected).
#
# Usage: tls_client.py <port> <ca.crt> <other-ca.crt>
#
import socket
import ssl
import sys

HOST = "127.0.0.1"


def connect(port, cafile):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.load_verify_locations(cafile=cafile)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    sock = socket.create_connection((HOST, port), timeout=10)
    return ctx.wrap_socket(sock, server_hostname=HOST)


def request(ss):
    ss.sendall(b"GET / HTTP/1.0\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n")


def read_all(ss, bufsize, timeout):
    ss.settimeout(timeout)
    data = b""
    while True:
        try:
            chunk = ss.recv(bufsize)
        except TimeoutError:
            if data:
                break
            raise
        if not chunk:
            break
        data += chunk
    return data


def main():
    port = int(sys.argv[1])
    ca = sys.argv[2]
    other_ca = sys.argv[3]
    print("candidate-linked CPython: %s" % sys.executable)
    print("ssl.OPENSSL_VERSION: %s" % ssl.OPENSSL_VERSION)

    print("\n[1] handshake + data, server cert trusted via our test CA")
    ss = connect(port, ca)
    cert = ss.getpeercert()
    cipher = ss.cipher()
    print("  negotiated_version = %r" % ss.version())
    print("  cipher             = %r  (None => candidate SSL_get_current_cipher returns NULL)" % (cipher[0] if cipher else None))
    print("  cert_present       = %r" % (cert is not None))
    print("  cert_subject       = %r" % (dict(x[0] for x in cert.get("subject", [])) if cert else None))
    request(ss)
    data = read_all(ss, 65536, 5)
    print("  DATA (16 KiB buffer) = ok, %d bytes, status %r"
          % (len(data), data.split(b"\r\n", 1)[0].decode("latin1")))
    ss.close()

    print("\n[2] verification must reject an unrelated CA")
    verify_enforced = False
    try:
        connect(port, other_ca).close()
        print("  VERIFY_NEGATIVE = FAIL: server cert accepted though signed by an unrelated CA")
    except ssl.SSLCertVerificationError as e:
        verify_enforced = True
        print("  VERIFY_NEGATIVE = ok, rejected (verify_code=%s)" % e.verify_code)

    print("\n[3] default small recv buffers (what a real consumer does)")
    for bufsize in (1024, 4096):
        ss = connect(port, ca)
        request(ss)
        try:
            read_all(ss, bufsize, 4)
            print("  recv(%d) = ok" % bufsize)
        except TimeoutError:
            print("  recv(%d) = TimeoutError: SSL_read_ex stalls when buffer < record size" % bufsize)
        finally:
            ss.close()

    if verify_enforced:
        print("\ntls_client.py: OK")
        return 0
    print("\ntls_client.py: FAILED — certificate verification is not enforced (transport/data work)")
    return 1


if __name__ == "__main__":
    sys.exit(main())
