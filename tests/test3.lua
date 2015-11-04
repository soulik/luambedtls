local bit = require 'bit'
local tls = require 'luambedtls'
require 'utils'
local dump = (require 'utils/dump').dump

-- SessionGetUserName() + GetHostName()
local encodedHex = [[A35C6E5C2C2E392F2F3E292E3B383D323F393A392F287239292C2E392F2F3E292E3B383D323F393A392F287239290434393030336C6D]]

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

--[[
uint8_t Result = (uint8_t)
      ~((((PWALG_SIMPLE_STRING.Pos(Str.c_str()[0])-1) << 4) +
         ((PWALG_SIMPLE_STRING.Pos(Str.c_str()[1])-1) << 0)) ^ PWALG_SIMPLE_MAGIC);
--]]

local function readMagic(str)
	local i0 = str:sub(1,1):byte()
	return i0 == 0xA3
end

--local key = 'pressburgdancefest.eupressburgdancefest.eu'
local key = [[Other/Petka/pressburgdancefest.eu@pressburgdancefest.eu]]
local encoded = encodedHex:gsub("(%x%x)", function(s) return string.char(tonumber(s, 16)) end)

-- iv, key - 16, 32

print(encoded:hex_dump {prefix='total '})

local magicLength = 1
local ivLength = 16
local macLength = 10

local magic, iv, msg, tag = encoded:sub(1, magicLength), encoded:sub(magicLength + 1, ivLength), encoded:sub(magicLength + ivLength + 1, #encoded - macLength), encoded:sub(-macLength)

local m = readMagic(magic)

print(magic:hex_dump {prefix='magic '})
print(iv:hex_dump {prefix='IV '})
print(msg:hex_dump {prefix='msg '})
print(tag:hex_dump {prefix='tag '})
print(key:hex_dump {prefix='key '})

print('Magic: ', m)

--local _key = key:sub(1, 32)

local iv2, decodedText = decrypt(key, iv, encoded, tag)

print(iv2, decodedText)
print(decodedText:hex_dump())
