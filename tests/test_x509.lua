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

local function OIDname(n)
	local r = tls.pushOIDAttrShortName(n)
	if type(r) == 'number' then
		return false
	else
		return r
	end
end

local function keyLength(key)
	return bit.rshift(key.N.bitLen + 7, 3)
end

local function printOID(name, attribute)
	local t = {}
	while attribute do
		local oname = OIDname(attribute.oid)
		if not oname then
			break
		end
		table.insert(t, ('%s:%s'):format(tostring(oname), tostring(attribute.val)))
		attribute = attribute.next
	end
	print(('%s\t%s'):format(name, table.concat(t, ' ')))
end

local function getSerial(s)
	assert(s.tag == tls.ASN1_INTEGER)
	local bytes = s.value
	if type(bytes)=='table' then
		local out = {}
		for _, b in ipairs(bytes) do
			table.insert(out, ('%X'):format(b))
		end
		return table.concat(out, ':')
	else
		return bytes
	end
end


local crt = tls.x509crt()
TLS_assert(crt.parseFile("google.crt"))
print(crt.info())

print('alt names:')
local currentAltName = crt.subjectAltNames

repeat 
	print('', currentAltName.buf)
	currentAltName = currentAltName.next
until not currentAltName

local CA = tls.x509crt()
TLS_assert(CA.parseFile("google_ia.crt"))
local CAcrl = tls.x509crl()

local result = TLS_assert(crt.verify(CA, CAcrl, nil, function(crt, depth, flags, info)
	print(("Depth: %d"):format(depth))
	print(('Serial: %s'):format(getSerial(crt.serial)))
	print(crt.info())
	if info then
		print('Verification:')
		print(info)
	end
end))

--printOID('issuer',crt.issuer)
--printOID('subject',crt.subject)
--print(crt.pk.bitLen)
