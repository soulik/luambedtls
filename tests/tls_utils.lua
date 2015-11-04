#!/usr/bin/luajit

local tls = require 'luambedtls'

local function setupGCdependencies(obj, ...)
	local mt = getmetatable(obj)
	if type(mt)=='table' then
		if type(mt.dependencies) ~= 'table' then
			mt.dependencies = {}
		end
		local dependencies = {...}
		for _,dependency in ipairs(dependencies) do
			table.insert(mt.dependencies, dependency)
		end
	end
end

local function tlsAssert(...)
	local arg = {...}
	if type(arg[1])=='number' and arg[1] < 0 then
		error(('mbed TLS error: "%s"'):format(tls.strError(arg[1])), 2)
	else
		return ...
	end
end

return {
	setupGCdependencies = setupGCdependencies,
	tlsAssert = tlsAssert,
}