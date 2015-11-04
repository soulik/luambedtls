#!/usr/bin/luajit

local bit = require 'bit'
local tls = require 'luambedtls'
require 'utils'

local function TLS_assert(...)
	local errn = select(1, ...)
	if type(errn)=='number' and errn ~= 0 then
		error(tls.strError(errn))
	else
		return ...
	end
end

local _type = type

local function type(o)
	local mt = getmetatable(o)
	if _type(mt)=='table' and _type(mt.__typename)=='function' then
		return mt.__typename()
	else
		return _type(o)
	end
end

local entropy = tls.EntropyContext()
local CTR_DRBG = tls.CTRDRBGContext()
CTR_DRBG.seed(entropy, "ecp_test")

local list = tls.ECPCurveList()
for k,v in ipairs(list) do
	print(("%-20s -\t(Group: %d, TLS: %d)\t%d-bits"):format(v.name, v.groupID,v.TLSID, v.bitSize))
end

--[[
local list = tls.ECPGroupIDList()
for k,v in ipairs(list) do
	print(k,v)
end
--]]

local originalText  = [[
Hello world! :)
]]

local curveID = tls.ECP_DP_SECP521R1

local keyPair = tls.ECPKeyPair()
TLS_assert(keyPair.genKey(curveID, CTR_DRBG))

local ECSDA = tls.ECSDAContext()
TLS_assert(ECSDA.fromKeypair(keyPair))

local mdType = mdType or tls.MD_SHA256
local hash = TLS_assert(tls.md(mdType, originalText))

print(hash:hex_dump {prefix='Hash: '})

local r, s = TLS_assert(ECSDA.sign(keyPair.group, keyPair.d, hash, CTR_DRBG))
local sign = TLS_assert(ECSDA.writeSignature(mdType, hash, CTR_DRBG))
print(sign:hex_dump {prefix='Signature: '})

local result = TLS_assert(ECSDA.verify(keyPair.group, hash, keyPair.Q, r, s))
print(result==0 and 'Verification successful' or 'Verification failed!')

local result = TLS_assert(ECSDA.readSignature(hash, sign))
print(result==0 and 'Verification successful' or 'Verification failed!')

local keyPair = tls.ECPKeyPair()
TLS_assert(keyPair.genKey(curveID, CTR_DRBG))

local ECDH = tls.ECDHContext()
ECDH.group.load(curveID)

TLS_assert(ECDH.getParams(keyPair, tls.ECDH_OURS))
local d, Q = TLS_assert(ECDH.genPublic(keyPair.group, CTR_DRBG))
ECDH.Qp = ECDH.Q

local public = TLS_assert(ECDH.makePublic(1024, CTR_DRBG))
local secret = TLS_assert(ECDH.calcSecret(1024, CTR_DRBG))
local params = TLS_assert(ECDH.makeParams(1024, CTR_DRBG))

params = params .. 'Additional data...'

print(public:hex_dump{prefix = 'Public: '})
print(secret:hex_dump{prefix = 'Secret: '})
print(params:hex_dump{prefix = 'Params: '})

TLS_assert(ECDH.readPublic(public))
local rest = TLS_assert(ECDH.readParams(params))
local z = TLS_assert(ECDH.computeShared(keyPair.group, Q, d, CTR_DRBG))

print(rest:hex_dump{prefix = 'Rest of data: '})

