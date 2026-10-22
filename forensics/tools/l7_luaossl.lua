-- lua-luaossl L7 workload: the module's digest and HMAC paths against fixed vectors, plus a
-- corrupted-input control that must produce a different HMAC.
local ok, openssl = pcall(require, "openssl")
if not ok then
    print("load=error")
    print(tostring(openssl))
    os.exit(2)
end

local digest = require("openssl.digest")
local hmac = require("openssl.hmac")
local function hex(s)
    local out = {}
    for i = 1, #s do
        out[i] = string.format("%02x", string.byte(s, i))
    end
    return table.concat(out)
end

local d = hex(digest.new("sha256"):final("abc"))
local good = hex(hmac.new("phase25-l7-key", "sha256")
                     :final("The quick brown fox jumps over the lazy dog"))
local bad = hex(hmac.new("phase25-l7-key", "sha256")
                    :final("The quick brown fox jumps over the lazy doG"))

print("sha256=" .. d)
print("hmac=" .. good)
print("sha256_vector=" .. (d ==
    "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad" and "ok" or "mismatch"))
print("hmac_vector=" .. (good ==
    "5e17407f837ce86a8fe1eb32a9d25900e5e45934914a4a017151535ee92eb094" and "ok" or "mismatch"))
print("wrong_input_differs=" .. (good ~= bad and "ok" or "same"))
