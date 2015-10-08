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

local alg = tls.CIPHER_AES_256_GCM

local cipher = tls.CipherContext()

local currentCipher = tls.cipherInfo(alg)
assert(currentCipher)

local blockSize = currentCipher.blockSize
local keySize = math.floor(currentCipher.bitLen / 8)
local iv = CTR_DRBG.random(currentCipher.IVsize)
local key = CTR_DRBG.random(keySize)

TLS_assert(cipher.setup(currentCipher))
cipher.paddingMode = tls.PADDING_PKCS7

local function encrypt(key, iv, input)
	TLS_assert(cipher.setKey(key, tls.ENCRYPT))
	return TLS_assert(cipher.authEncrypt(iv, input, #input + blockSize, 16))
end

local function decrypt(key, iv, input, tag)
	TLS_assert(cipher.setKey(key, tls.DECRYPT))
	return TLS_assert(cipher.authDecrypt(iv, input, tag, #input + blockSize))
end

local cipherText, tag = encrypt(key, iv, originalText)
print(cipherText:hex_dump())

local decodedText = decrypt(key, iv, cipherText, tag)

dump(decodedText)
