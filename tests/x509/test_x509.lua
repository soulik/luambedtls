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


local crt = tls.x509crt()
TLS_assert(crt.parseFile("subject_signed.crt"))
print(crt.info())

local CA = tls.x509crt()
TLS_assert(CA.parseFile("CA.crt"))
local CAcrl = tls.x509crl()
--print(CA.info())

local result = TLS_assert(crt.verify(CA, CAcrl, nil, function(crt, depth, flags, info)
	print(("Depth: %d"):format(depth))
	print(dump(crt.serial.value, 'Serial'))
	print(crt.info())
	if info then
		print('Verification:')
		print(info)
	end
end))

--printOID('issuer',crt.issuer)
--printOID('subject',crt.subject)
--print(crt.pk.bitLen)
