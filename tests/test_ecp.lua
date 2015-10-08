local bit = require 'bit'
local tls = require 'luambedtls'
require 'utils'
local dump = (require 'utils/dump').dump

local function TLS_assert(...)
	local errn = select(1, ...)
	if type(errn)=='number' and errn ~= 0 then
		error(tls.strError(errn))
	else
		return ...
	end
end

local list = tls.ECPCurveList()
for k,v in ipairs(list) do
	print(k,v.name)
end

local list = tls.ECPGroupIDList()
for k,v in ipairs(list) do
	print(k,v)
end