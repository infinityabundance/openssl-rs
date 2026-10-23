// S23 L7 workload: cpp-httplib's SSLServer/SSLClient over verified TLS.
//
// The harness is a *consumer* of the family's own header-only library, rebuilt in the
// pristine tree against the subject OpenSSL.  It runs both ends in one process: a local
// HTTPS server serving a fixed body, and an SSLClient that verifies the chain against
// the fixture CA.  A second client trusting an unrelated CA must fail to connect.
//
// Usage: l7-httplib-harness <server-cert> <server-key> <trusted-ca> <unrelated-ca>
#define CPPHTTPLIB_OPENSSL_SUPPORT
#include "httplib.h"

#include <cstdio>
#include <string>
#include <thread>

int main(int argc, char **argv) {
  if (argc != 5) {
    std::fprintf(stderr, "usage: %s cert key ca unrelated-ca\n", argv[0]);
    return 2;
  }
  const std::string cert = argv[1], key = argv[2], ca = argv[3], badca = argv[4];

  httplib::SSLServer server(cert.c_str(), key.c_str());
  if (!server.is_valid()) {
    std::fprintf(stderr, "S23-FAIL server context\n");
    return 1;
  }
  server.Get("/", [](const httplib::Request &, httplib::Response &res) {
    res.set_content("s23-httplib", "text/plain");
  });
  int port = server.bind_to_any_port("127.0.0.1");
  if (port <= 0) {
    std::fprintf(stderr, "S23-FAIL bind\n");
    return 1;
  }
  std::thread serving([&server] { server.listen_after_bind(); });

  int rc = 1;
  {
    httplib::SSLClient client("127.0.0.1", port);
    client.set_ca_cert_path(ca.c_str());
    client.enable_server_certificate_verification(true);
    client.set_connection_timeout(5, 0);
    client.set_read_timeout(5, 0);
    auto res = client.Get("/");
    if (!res || res->status != 200 || res->body != "s23-httplib") {
      std::fprintf(stderr, "S23-FAIL trusted fetch: %s\n",
                   res ? ("status " + std::to_string(res->status)).c_str() : "no response");
    } else {
      httplib::SSLClient bad("127.0.0.1", port);
      bad.set_ca_cert_path(badca.c_str());
      bad.enable_server_certificate_verification(true);
      bad.set_connection_timeout(5, 0);
      bad.set_read_timeout(5, 0);
      auto badres = bad.Get("/");
      if (badres && badres->status == 200) {
        std::fprintf(stderr, "S23-FAIL unrelated CA accepted\n");
      } else {
        std::printf("S23-PASS TLS verified fetch, unrelated CA rejected\n");
        rc = 0;
      }
    }
  }
  server.stop();
  serving.join();
  return rc;
}
