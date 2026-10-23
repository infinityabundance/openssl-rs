# S33: Ruby 3.1's ext/openssl over PKCS#12, PKCS#7, OCSP, X.509 verification and raw keys.
require 'openssl'

cert = OpenSSL::X509::Certificate.new(File.read(ARGV[0]))
key = OpenSSL::PKey.read(File.read(ARGV[1]))
ca = OpenSSL::X509::Certificate.new(File.read(ARGV[2]))
other = OpenSSL::X509::Certificate.new(File.read(ARGV[3]))

store = OpenSSL::X509::Store.new
store.add_file(ARGV[2])
puts "ruby_store_verify=" + (store.verify(cert) ? "ok" : "bad")

p12 = OpenSSL::PKCS12.create("s33pass", "s33", key, cert, [ca])
puts "ruby_pkcs12_export=" + (p12.to_der.bytesize > 0 ? "ok" : "bad")
parsed = OpenSSL::PKCS12.new(p12.to_der, "s33pass")
puts "ruby_pkcs12_read=" + (parsed.certificate.subject.to_s.include?("127.0.0.1") ? "ok" : "bad")

p7 = OpenSSL::PKCS7.sign(cert, key, "s33 ruby pkcs7", [ca], OpenSSL::PKCS7::BINARY)
puts "ruby_pkcs7_sign=" + (p7.to_der.bytesize > 0 ? "ok" : "bad")
puts "ruby_pkcs7_verify=" + (p7.verify([ca], store, nil, OpenSSL::PKCS7::NOVERIFY) ? "ok" : "bad")

cid = OpenSSL::OCSP::CertificateId.new(cert, ca)
req = OpenSSL::OCSP::Request.new
req.add_certid(cid)
der = req.to_der
req2 = OpenSSL::OCSP::Request.new(der)
puts "ruby_ocsp_request=" + (req2.certid.length == 1 ? "ok" : "bad")

ed = OpenSSL::PKey.generate_key("ED25519")
sig = ed.sign(nil, "s33 ed25519")
puts "ruby_ed25519_sign=" + (sig.bytesize > 0 ? "ok" : "bad")
puts "ruby_ed25519_verify=" + (ed.verify(nil, sig, "s33 ed25519") ? "ok" : "bad")

puts "ruby_unrelated_ca_rejected=" + (store.verify(other) ? "bad" : "rejected")
