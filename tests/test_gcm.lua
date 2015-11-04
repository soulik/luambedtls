#!/usr/bin/luajit

local bit = require 'bit'
local tls = require 'luambedtls'
require 'utils'

local originalText  = [[
Lorem ipsum dolor sit amet, consectetur adipiscing elit. Suspendisse a malesuada turpis.
Aliquam ullamcorper felis id venenatis tristique.
Phasellus dignissim lectus a tellus scelerisque volutpat.
Quisque maximus molestie ullamcorper.
Nulla posuere dolor vitae erat imperdiet, sit amet egestas lacus maximus.
Nullam vel rhoncus sem. Etiam nunc neque, malesuada id fringilla eu, mattis vitae dolor.
Ut tincidunt pellentesque tortor eu sagittis.
Vestibulum id nibh justo. Praesent vitae ante eu diam fermentum sagittis.
Integer mollis pellentesque urna non sodales.
Vestibulum ante nulla, semper et varius eu, porttitor quis nunc.
Cras vel mauris mauris.]]

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
CTR_DRBG.seed(entropy, "rsatest")
local alg = tls.CIPHER_ID_AES

local gcm = tls.GCMContext()
local iv = CTR_DRBG.random(16)
local key = CTR_DRBG.random(32)

local function encrypt(key, iv, input)
	gcm.setKey(alg, key)
	return TLS_assert(gcm.cryptAndTag(tls.GCM_ENCRYPT, iv, input, 16))
end

local function decrypt(key, iv, input, tag)
	gcm.setKey(alg, key)
	return TLS_assert(gcm.authDecrypt(iv, input, tag))
end
local cipherText

local cipherText, tag = encrypt(key, iv, originalText)
print(cipherText:hex_dump())

local decodedText = decrypt(key, iv, cipherText, tag)

dump(decodedText)
