local zmq = require 'zmq'
local ztransport = require 'ztransport'

local context = assert(zmq.context())

local function buffer(_data, _len)
	local _data = _data or ''
	local _len = _len or 0

	local obj = {
	}

	obj.read = function(len0)
		if len0 and (len0 < _len) then
			local out = _data:sub(1, len0)
			_data = _data:sub(len0 + 1)
			_len = _len - len0
			return out, len0
		else
			local out = _data
			local outLen = _len
			_data = ''
			_len = 0
			return out, outLen
		end
	end

	obj.write = function(data, len)
		if _len>0 then
			_data = _data .. data
			_len = _len + len
		else
			_data = data
			_len = len
		end
	end

	obj.clear = function()
		_data = ''
		_len = 0
	end

	obj.empty = function()
		return _len <= 0
	end

	return obj
end

local function TCP(options)
	local options = options or {}
	local host = options.host or 'localhost'
	local port = options.port or 80
	local socket = assert(context.socket(zmq.ZMQ_STREAM))
	local identity
	socket.options.stream_notify = true
	socket.options.ipv6 = true

	local recvDataBuffers = {
	}
	local sendDataBuffers = {
	}
	local identities = {}

	for _, t in ipairs {recvDataBuffers, sendDataBuffers, identities} do
		setmetatable(t, {__mode='k'})
	end

	for _, t in ipairs {recvDataBuffers, sendDataBuffers} do
		local mt = getmetatable(t)
		mt.__index = function(storage, socket)
			local dataBuffer = rawget(storage, socket)
			if not dataBuffer then
				dataBuffer = buffer(); rawset(storage,socket,dataBuffer)
			end
			return dataBuffer		
		end
	end

	local function s_sendData(socket, id, data)
		assert(socket.send(id, zmq.ZMQ_SNDMORE))
		return assert(socket.send(data, zmq.ZMQ_SNDMORE))
	end

	local function s_recvData(socket, len0, t)
		local dataBuffer = recvDataBuffers[socket]

		if dataBuffer and not dataBuffer.empty() then
			local len, data = dataBuffer.read(len0)
			return dataBuffer.ID, data, len
		else
			local id = assert(socket.recv(16))
			local data, len = assert(socket.recv(BUFFER_SIZE))
			if len > len0 then
				local dataBuffer = recvDataBuffers[socket]
				if not dataBuffer then
					dataBuffer = buffer(data, len, id); recvDataBuffers[socket] = dataBuffer
				else
					dataBuffer.write(data, len)
				end
				return id, dataBuffer.read(len0)
			else
				return id, data, len
			end
		end
	end

	local function recvFn(socket)
		local dataBuffer = recvDataBuffers[socket]

		local id = assert(socket.recv(16))
		local data, len = assert(socket.recv(BUFFER_SIZE))

		if not identities[socket] then
			identities[socket] = id
		end

		if len>0 then
			dataBuffer.write(data, len)
		end
 	end

	local function sendFn(socket)
		local dataBuffer = sendDataBuffers[socket]

		if not dataBuffer.empty() then
			local data, len = dataBuffer.read()
			local id = identities[socket] or identity
			local bsent = 0

			if id then
				assert(socket.send(id, zmq.ZMQ_SNDMORE))
				bsent = assert(socket.send(data, zmq.ZMQ_SNDMORE))

				if bsent < len then
					local data1 = data:sub(bsent+1)
					dataBuffer.write(data1, #data1)
				end
			end
		end
 	end

	local recvPoll = zmq.poll {
		{socket, zmq.ZMQ_POLLIN, recvFn},
	}

	local sendPoll = zmq.poll {
		{socket, zmq.ZMQ_POLLOUT, sendFn},
	}

	local function sendData(data, id)
		--local id = id or identity
		--return s_sendData(socket, id, data)

		local dataBuffer = sendDataBuffers[socket]
		
		dataBuffer.write(data, #data)

		while not dataBuffer.empty() do
			sendPoll.start()
		end
		return #data
	end

	local function recvData(len0, t)
		--return s_recvData(socket, len0, t)
		local dataBuffer = recvDataBuffers[socket]
		while dataBuffer.empty() do
			if t then
				recvPoll.start(t)
			else
				recvPoll.start()
			end
		end

		--local id = identities[socket]
		return dataBuffer.read(len0)
	end

	local function init()
		local addr = ("tcp://%s:%d"):format(host, port)
		if options.debug then
			print('Connecting to', addr)
		end
		assert(socket.connect(addr))
		identity = socket.options.identity
		if options.debug then
			print(identity:hex_dump{tabs=1, prefix='Client ID - '})
		end
	end

	local function close()
		assert(socket.send(identity, zmq.ZMQ_SNDMORE))
		assert(socket.send(''))
		socket.disconnect()
	end

	return {
		init = init,
		close = close,
		recv = recvData,
		send = sendData,
	}
end

return {
	new = ztransport.wrap(TCP),
}