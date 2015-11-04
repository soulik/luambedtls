#!/usr/bin/luajit

local bit = require 'bit'
local tls = require 'luambedtls'
require 'utils'

local originalText  = [[
Hello world! :)
]]

local entropy = tls.EntropyContext()
local CTR_DRBG = tls.CTRDRBGContext()
CTR_DRBG.seed(entropy, "rsatest")

local function keyLength(key)
	return bit.rshift(key.N.bitLen + 7, 3)
end

local function TLS_assert(...)
	local errn = select(1, ...)
	if type(errn)=='number' and errn ~= 0 then
		error(tls.strError(errn))
	else
		return ...
	end
end
 
local function encrypt(input, key)
	local rsa = tls.RSAContext(tls.RSA_PKCS_V15, 0)
	rsa.N = key.N
	rsa.E = key.E

	rsa.len = keyLength(key)
	TLS_assert(rsa.checkPubKey())

	return TLS_assert(rsa.encryptPKCS1(CTR_DRBG, tls.RSA_PUBLIC, input))
end

local function decrypt(input, key)
	local rsa = tls.RSAContext(tls.RSA_PKCS_V15, 0)
	rsa.N = key.N
	rsa.E = key.E
	rsa.D = key.D
	rsa.P = key.P
	rsa.Q = key.Q
	rsa.DP = key.DP
	rsa.DQ = key.DQ
	rsa.QP = key.QP

	rsa.len = keyLength(key)
	TLS_assert(rsa.checkPrivKey())

	return TLS_assert(rsa.decryptPKCS1(CTR_DRBG, tls.RSA_PRIVATE, input, 1024))
end

local function genKey(keySize, exponent)
	local keys = {
		private = {},
		public = {},
	}
	local rsa = tls.RSAContext(tls.RSA_PKCS_V15, 0)
	TLS_assert(rsa.genKey(CTR_DRBG, keySize, exponent))
	keys.public.N = rsa.N
	keys.public.E = rsa.E

	keys.private.N = rsa.N
	keys.private.E = rsa.E
	keys.private.D = rsa.D
	keys.private.P = rsa.P
	keys.private.Q = rsa.Q
	keys.private.DP = rsa.DP
	keys.private.DQ = rsa.DQ
	keys.private.QP = rsa.QP
	return keys
end

local function sign(data, key, mdType)
	local mdType = mdType or tls.MD_SHA256
	local rsa = tls.RSAContext(tls.RSA_PKCS_V15, 0)
	rsa.N = key.N
	rsa.E = key.E
	rsa.D = key.D
	rsa.P = key.P
	rsa.Q = key.Q
	rsa.DP = key.DP
	rsa.DQ = key.DQ
	rsa.QP = key.QP
	rsa.len = keyLength(key)
	
	TLS_assert(rsa.checkPrivKey())

	local hash = tls.md(mdType, data)

	return TLS_assert(rsa.signPKCS1(CTR_DRBG, tls.RSA_PRIVATE, mdType, hash))
end

local function verify(data, key, sign, mdType)
	local mdType = mdType or tls.MD_SHA256
	local rsa = tls.RSAContext(tls.RSA_PKCS_V15, 0)
	rsa.N = key.N
	rsa.E = key.E
	rsa.len = keyLength(key)
	
	TLS_assert(rsa.checkPubKey())

	local hash = tls.md(mdType, data)

	return rsa.verifyPKCS1(CTR_DRBG, tls.RSA_PUBLIC, mdType, hash, sign) == 0
end

local keys = genKey(1024, 65537)

local cipherText = encrypt(originalText, keys.public)
print(cipherText:hex_dump {prefix = "Ciphertext: "} )

local decryptedText = decrypt(cipherText, keys.private)
print(decryptedText:hex_dump {prefix = "Decrypted text: "} )

local s = sign(originalText, keys.private)
print(s:hex_dump {prefix = "Sign: "} )

print(("Verification result: %s"):format(tostring(verify(originalText, keys.public, s))))


