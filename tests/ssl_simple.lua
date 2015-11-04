#!/usr/bin/luajit

local tls = require 'luambedtls'
local tls_utils = require 'tls_utils'
require 'utils'
local ztransport = require 'ztransport'
local setupGCdependencies, tlsAssert = tls_utils.setupGCdependencies, tls_utils.tlsAssert

local M = {}

local function SSL(options)
	local obj = {}
	local options = options or {}
	local entropy = tls.EntropyContext()
	local CTR_DRBG = tls.CTRDRBGContext()
	local ssl = tls.SSLContext()
	local sslConfig
	local CAcert = tls.x509crt()
	local session = tls.SSLSession()
	local timer = tls.TimingDelayContext()

	obj.callbacks = options.callbacks or {
		send = function(msg)
			return #msg
		end,
		recv = function(len)
			local msg = ''
			return #msg, msg
		end,
		recvTimeout = function(len, timeout)
			local msg = ''
			return #msg, msg
		end,
		close = function()
		end,
		init = function()
		end,
	}

	obj.handshake = function()
		local ret = 0
		repeat
			ret = ssl.handshake()
		until (ret ~= tls.ERR_SSL_WANT_READ and ret ~= tls.ERR_SSL_WANT_WRITE)
		tlsAssert(ret)
		tlsAssert(ssl.verifyResult)
	end

	obj.send = function(msg)
		local ret = 0
		repeat
			ret = ssl.write(msg)
		until (ret ~= tls.ERR_SSL_WANT_READ and ret ~= tls.ERR_SSL_WANT_WRITE)
		tlsAssert(ret)
	end

	obj.recv = function(len)
		local ret, str
		repeat
			ret, str = ssl.read(len)
		until (ret ~= tls.ERR_SSL_WANT_READ and ret ~= tls.ERR_SSL_WANT_WRITE)

		if (ret <= 0) then
			if ret == tls.ERR_SSL_TIMEOUT then
				printf( " timeout\n\n" )
			elseif ret == tls.ERR_SSL_PEER_CLOSE_NOTIFY then
				--printf( " connection was closed gracefully\n" )
				return false
			else
				error('read error')
			end
		end
		return str, ret
	end

	obj.close = function()
		local ret = 0
		repeat
			ret = ssl.closeNotify()
		until (ret ~= tls.ERR_SSL_WANT_WRITE)

		obj.callbacks.close()
		ssl = nil
		collectgarbage()
		sslConfig = nil
		collectgarbage()
	end

	obj.init = function()
		tlsAssert(CTR_DRBG.seed(entropy, "sslclient"))
		local ret = tlsAssert(CAcert.parse(options.CAcert))

		sslConfig = tlsAssert(tls.SSLConfig(tls.SSL_IS_CLIENT, tls.SSL_TRANSPORT_STREAM, tls.SSL_PRESET_DEFAULT))
		setupGCdependencies(ssl, sslConfig)

		sslConfig.authmode = tls.SSL_VERIFY_OPTIONAL
		sslConfig.setCAChain(CAcert)
		sslConfig.setRNG(CTR_DRBG)

		if options.debug then
			sslConfig.setDBG(true)
			tls.debugTreshhold(4)
		end

		--sslConfig.minVersion(tls.SSL_MAJOR_VERSION_3, ssl.SSL_MINOR_VERSION_1)
	
		tlsAssert(ssl.setup(sslConfig))
		tlsAssert(ssl.setHostname(options.hostname or "localhost"))

		ssl.setBIO(obj.callbacks.send, obj.callbacks.recv, obj.callbacks.recvTimeout)
		ssl.setTimer(timer)

		obj.callbacks.init()
		obj.handshake()
	end

	return obj
end

M.new = ztransport.wrap(SSL)

return M
