local bit = require 'bit'
local tls = require 'luambedtls'
local dump = (require 'utils/dump').dump
require 'utils'

local originalText  = [[
Hello world! :)
]]

local function TLS_assert(...)
	local errn = select(1, ...)
	if type(errn)=='number' and errn ~= 0 then
		error(tls.strError(errn))
	else
		return ...
	end
end
 
local algs = tls.mdList()
for _, id in ipairs(algs) do
	local alg = tls.mdInfo(id)
	print(alg.name, alg.size, alg.blockSize)
	local hash = (alg.md(originalText)):sub(1, alg.size)
	print(hash:hex_dump())
end

