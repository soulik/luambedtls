#!/usr/bin/luajit

local bit = require 'bit'
local tls = require 'luambedtls'
require 'utils'

local originalText  = [[
Lorem ipsum dolor sit amet.
]]

local function TLS_assert(...)
	local errn = select(1, ...)
	if type(errn)=='number' and errn ~= 0 then
		error(tls.strError(errn))
	else
		return ...
	end
end

local entropy = tls.EntropyContext()
local CTR_DRBG = tls.CTRDRBGContext()
CTR_DRBG.seed(entropy, "pktest")

local pkType = tls.PK_ECKEY

if arg[1] then
	if arg[1] == 'ec' then
		pkType = tls.PK_ECKEY
	elseif arg[1] == 'rsa' then
		pkType = tls.PK_RSA
	end
end

local pkInfo = tls.PKinfoFromType(pkType)
assert(pkInfo)

local pk = tls.PKContext()
TLS_assert(pk.setup(pkInfo))

local function keyLength(key)
	return bit.rshift(key.N.bitLen + 7, 3)
end

local function setPublicKey(dest, key)
	dest.N = key.N
	dest.E = key.E

	dest.len = keyLength(key)
end

local function setPrivateKey(dest, key)
	dest.N = key.N
	dest.E = key.E
	dest.N = key.N
	dest.E = key.E
	dest.D = key.D
	dest.P = key.P
	dest.Q = key.Q
	dest.DP = key.DP
	dest.DQ = key.DQ
	dest.QP = key.QP

	dest.len = keyLength(key)
end

local function genRSAKey(keySize, exponent)
	local rsa = pk.rsa
	local keys = {
		private = {},
		public = {},
	}
	TLS_assert(rsa.genKey(CTR_DRBG, keySize, exponent))

	setPublicKey(keys.public, rsa)
	setPrivateKey(keys.private, rsa)

	return keys
end

local function genECKey()
	local curveID = tls.ECP_DP_SECP256R1
	local ec = pk.ec
	local keys = {
		private = {},
		public = {},
	}
	TLS_assert(ec.genKey(curveID, CTR_DRBG))

	--setPublicKey(keys.public, rsa)
	--setPrivateKey(keys.private, rsa)

	return keys
end

local function genKey(keySize, exponent)
	if pkType == tls.PK_ECKEY then
		return genECKey()
	elseif pkType == tls.PK_RSA then
		return genRSAKey(keySize, exponent)
	end
end

local function encrypt(input, key)
	local rsa = pk.rsa
	setPublicKey(rsa, key)
	TLS_assert(rsa.checkPubKey())
	return TLS_assert(pk.encrypt(CTR_DRBG, input, key.N.size))
end

local function decrypt(input, key)
	local rsa = pk.rsa
	setPrivateKey(rsa, key)
	TLS_assert(rsa.checkPrivKey())

	return TLS_assert(pk.decrypt(CTR_DRBG, input, 2048))
end

local function sign(data, key, mdType)
	local rsa = pk.rsa
	local mdType = mdType or tls.MD_SHA256
	setPrivateKey(rsa, key)
	
	TLS_assert(rsa.checkPrivKey())

	local hash = tls.md(mdType, data)
	return TLS_assert(pk.sign(CTR_DRBG, mdType, hash, key.N.size))
end

local function verify(data, key, sign, mdType)
	local rsa = pk.rsa
	local mdType = mdType or tls.MD_SHA256
	setPublicKey(rsa, key)
	
	TLS_assert(rsa.checkPubKey())

	local hash = tls.md(mdType, data)

	return TLS_assert(pk.verify(mdType, hash, sign)) == 0
end

local keys = genKey(2048, 65537)

local privateKeyPEM = TLS_assert(pk.writeKeyPEM(2048))
local publicKeyPEM = TLS_assert(pk.writePublicKeyPEM(2048))
privateKeyPEM = privateKeyPEM:sub(1,privateKeyPEM:find("\0"))
publicKeyPEM = publicKeyPEM:sub(1,publicKeyPEM:find("\0"))

local name = arg[2] or 'subject'

io.save(('%s.key'):format(name), privateKeyPEM)
io.save(('%s.pub'):format(name), publicKeyPEM)

