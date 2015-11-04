local zhttp = require 'zhttp'

--[==[
local uri = require 'utils/parse/uri'

local test = uri.parse

local test_uris = {
[[ftp://ftp.is.co.za/rfc/rfc1808.txt]],
[[ftp://username:password@ftp.is.co.za:21/rfc/rfc1808.txt]],
[[http://www.ietf.org/rfc/rfc2396.txt]],
[[ldap://[2001:db8::7]/c=GB?objectClass?one]],
[[mailto:John.Doe@example.com]],
[[news:comp.infosystems.www.servers.unix]],
[[tel:+1-816-555-1212]],
[[telnet://192.0.2.16:80/]],
[[urn:oasis:names:specification:docbook:dtd:xml:4.1.2]],
[[ftp://cnn.example.com&story=breaking_news@10.0.0.1/top_story.htm]],
}

for _, uri in ipairs(test_uris) do
	local t = test(uri)
	print(uri)
	for k,v in pairs(t) do
		print('\t', k,v)
	end
end
--]==]

local h = zhttp.new('https://www.google.com/', {debugSSL = false,})

local f = io.open('out.bin', 'wb')
local n = 0
local chunks = 0
local hdr 

-- http://vps.soulik.eu/graphics.py
for header, data in h.request {} do
	n = n + #data
	chunks = chunks + 1
	f:write(data)
	if not hdr then
		for k,v in pairs(header) do
			print(k,v)
		end
	end
	hdr = hdr or header
end
print('Stats', n, hdr['Content-Length'], chunks)
f:close()

h.close()
