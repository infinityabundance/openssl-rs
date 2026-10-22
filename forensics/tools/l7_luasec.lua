-- lua-sec L7 workload: a real TLS client handshake and payload round trip against the loopback
-- server in l7_luasec.c, using the LuaSec binding. arg[1] is the CA file and arg[2] the port;
-- the wrong-CA control makes the handshake fail and reports `negative=rejected`.
local socket = require("socket")
local ssl = require("ssl")

local cafile = assert(arg[1], "missing CA file")
local port = assert(tonumber(arg[2]), "missing port")

local tcp = assert(socket.tcp())
tcp:settimeout(5)
assert(tcp:connect("127.0.0.1", port))

local params = {
    mode = "client",
    protocol = "tlsv1_3",
    verify = "peer",
    cafile = cafile,
    options = {"all"},
}

local conn, err = ssl.wrap(tcp, params)
if not conn then
    print("negative=rejected")
    print("tls_error=" .. tostring(err))
    os.exit(0)
end

local ok, herr = conn:dohandshake()
if not ok then
    print("negative=rejected")
    print("tls_error=" .. tostring(herr))
    os.exit(0)
end

local sent = conn:send("phase25-l7-luasec-ping\n")
if not sent then
    print("handshake=ok")
    print("payload=send-failed")
    os.exit(3)
end

local line, rerr = conn:receive("*l")
if line ~= "phase25-l7-luasec-pong" then
    print("handshake=ok")
    print("payload=unexpected:" .. tostring(line) .. ":" .. tostring(rerr))
    os.exit(3)
end

print("handshake=ok")
print("payload=" .. line)
conn:close()
os.exit(0)
