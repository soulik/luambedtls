local ztcp = require 'ztcp'
local uri = require 'utils/parse/uri'
local http = require 'utils/parse/http'
local ssl = require 'ssl_simple'
require 'utils'

local ti, tc = table.insert, table.concat

local NL = "\r\n"
local NLNL = NL..NL
local BUFFER_SIZE = 1024*8 -- 8kB JUMBO frames

local M = {}

local function splitHTTPResponse(data)
	assert(type(data)=='string')
	local delimPos =  data:find(NLNL, 1, true)
	if delimPos then
		local headerData = data:sub(1, delimPos)
		local bodyData = data:sub(delimPos + 4)
		return headerData, bodyData
	else
		return "", ""
	end
end

local function decodeHeader(headerData)
	assert(type(headerData)=='string')
	local parts = {}
	local first = true
	for part in headerData:gmatch("(.-)"..NL) do
		-- HTTP response code
	    if first then
	    	local response = http.response:match(part)
	    	assert(type(response)=='table', 'Invalid response')

			parts.status = {
				version = response.version,
				code = response.code,
				text = response.status,
			}
			first = false
	    else
	    	local item = http.headerItem:match(part)
	    	assert(type(item)=='table', 'Invalid header item')
	    	parts[item.name] = item.value
		end
	end
	return parts
end

local function HTTP(options)
	local options = options or {}
	local obj = {}
	local transports = {
		ztcp.new(options)
	} or options.transports

	local status = 0
	local transport

	if options.ssl then
		table.insert(transports,
			ssl.new {
				debug = options.debugSSL,
				hostname = options.host,
			}
		)
	end

	if type(transports)=='table' then
		if #(transports) > 0 then
			for _, t in ipairs(transports) do
				if not transport then
					transport = t
				else
					transport = transport + t
				end
			end
		else
			transport = transports
		end
	end

	transport.init()
	status = 1

	obj.request = function(data)
		local output = {}
		transport.send(data)
		if options.debug then
			print(data:hex_dump{tabs=1, prefix='Send - '})
		end
		local header
		local first = true
		local contentLength = -1
		local readBytes = 0
		local response, responseLen = "", 0

		return function()
			if status >= 1 then
				local response, responseLen = transport.recv(BUFFER_SIZE)
				if responseLen then
					if responseLen > 0 then
						if options.debug then
							print(response:hex_dump {tabs=1, prefix='Recv - '})
						end
					else
						response = ""
			    	end
			    else
			    	status = 0
					responseLen = 0
				end

				
				if responseLen>0 then
					if first then
						first = false
						header, response = splitHTTPResponse(response)

						header = decodeHeader(header)
						readBytes = readBytes + #response
						if header['Content-Length'] then
							contentLength = tonumber(header['Content-Length'])
						end
					else
						assert(type(header)=='table')
						if not contentLength and header['Content-Length'] then
							contentLength = tonumber(header['Content-Length'])
						end
						readBytes = readBytes + responseLen
					end

					if contentLength>=0 then
						if readBytes >= contentLength then
							status = 0
							local skipBytes = (readBytes-contentLength)
							if skipBytes>0 and false then
								local truncatedLen = responseLen - skipBytes
								return header, response:sub(1, truncatedLen)
							end
						end
					end

					return header, response
	        	else
	        		return header, ''
	        	end
			else
				return nil
			end
		end
	end

	obj.close = function()
		if transport then
			transport.close()
		end
	end

	return obj
end

local function HTTPheader(params)
	local params = params or {}
	local rT = {}
	params.method = params.method or "GET"
	params.url = params.url or '/'
	params.accept = params.accept or "*/*"

	ti(rT, ("%s %s HTTP/1.1"):format(params.method, params.url))
	ti(rT, ("Host: %s"):format(params.host))
	ti(rT, ("Accept: %s"):format(params.accept))
	ti(rT, NL)

	return tc(rT, NL)
end

M.new = function(URIstr, options)
	local URI = uri.parse(URIstr)
	assert(URI, 'Invalid URI')
	if URI.scheme == 'http' or URI.scheme == 'https' then
		local host = URI.host or 'localhost'
		local port = URI.port or ( (URI.scheme == 'https') and 443 or 80)
		local options = options or {}
		options.host = options.host or host
		options.port = options.port or port
		options.ssl = (URI.scheme == 'https')

		local h = HTTP(options)
		local obj = {}
		
		obj.request = function(options)
			options = options or {}
			options.host = options.host or host
			options.url = (options.url or URI.path) or '/'

			return h.request(HTTPheader(options))
		end

		obj.close = h.close

		return obj
	end
end

return M