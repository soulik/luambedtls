#!/usr/bin/luajit

local tls = require 'luambedtls'

local ciphers = tls.ciphersuites()

for k,v in pairs(ciphers) do
	print(k,v)
end