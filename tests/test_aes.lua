local bit = require 'bit'
local tls = require 'luambedtls'
require 'utils'
local dump = (require 'utils/dump').dump

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

local aes = tls.AESContext()
local iv = CTR_DRBG.random(16)
local key = CTR_DRBG.random(32)

local function addPadding(input, paddingChar)
	local paddingChar = paddingChar or "="
	local length = #input
	if length%16 ~= 0 then
		local newLength = math.ceil(length/16)*16
		return input .. paddingChar:rep(newLength-length)
	else
		return input
	end
end

local function encrypt(key, iv, input)
	aes.setKeyEnc(key)
	return TLS_assert(aes.cryptCBC(tls.AES_ENCRYPT, iv, addPadding(input)))
end

local function decrypt(key, iv, input)
	aes.setKeyDec(key)
	return TLS_assert(aes.cryptCBC(tls.AES_DECRYPT, iv, input))
end

local iv2, cipherText = encrypt(key, iv, originalText)
local iv2, decodedText = decrypt(key, iv, cipherText)

print(cipherText:hex_dump())
dump(decodedText)
