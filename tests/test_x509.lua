local bit = require 'bit'
local tls = require 'luambedtls'
require 'utils'

local OIDname = tls.pushOIDAttrShortName

local function keyLength(key)
	return bit.rshift(tls.MPIlen(key.N, 16) + 7, 3)
end

local function TLS_assert(...)
	local errn = select(1, ...)
	if type(errn)=='number' and errn ~= 0 then
		error(tls.strError(errn))
	else
		return ...
	end
end

local function printOID(attribute)
	while attribute do
		print(OIDname(attribute.oid), attribute.val)
		attribute = attribute.next
	end
end

local crt = tls.x509crt()
TLS_assert(crt.parseFile("PSCACA2.crt"))

print(crt.info())

print('issuer')
printOID(crt.issuer)
print('subject')
printOID(crt.subject)
print('subject')
printOID(crt.subject)
print(crt.pk.bitLen)
