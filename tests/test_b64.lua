local bit = require 'bit'
local tls = require 'luambedtls'
local dump = (require 'utils/dump').dump
require 'utils'

local function TLS_assert(...)
	local errn = select(1, ...)
	if type(errn)=='number' and errn ~= 0 then
		error(tls.strError(errn))
	else
		return ...
	end
end

local b64decode = tls.base64Decode
 
--[[
    <string name="fek"></string>
    <string name="pushRegistrationId"></string>
--]]

local _fek = "oSc0BQ/DBsfFDHorxsngUH4nXZppEb+EerXSv6jm/Fc="
local _regID = "APA91bHoZkp0Qd3aeh4yfIMpgOEJ0i-B-mszQqv-nKHctQGGlfsTD6nnujQw3607M82kJDltIE_6ipYJsksS1Axu8HYieGQFD3X9qEZ24Th2gMiXvLQDxevhVVBLSWfvVDZDiVrDt0UW"
local _per = "GAIHWcjf8e5LyNJE4qrXQHCsB/aKIH0g9DYcfuQ0w/WbSEX0XOubsw2kWVR/YIyspS5fgRdG83vQyrClDxD0QAQAhKSGFysp53gIUF5heGg0G88m4Txpg8mUccErN9/NBt0trd6OKtXnPlUenH9W65qdNgsNwrutGutIHSOv7/Rvz6ohpMSqM6y3YVDiGASwMgIH/gF3sD4/qQ2pDwJmH6gGVzjvm9Pz1WlnoQ4mXAsUHOGfDgckgBqqK/f7zx2ClC1U0cispoMD+9fn08zkum2pBK/nMdvPADWq0NA+MaM="

local fek = TLS_assert(b64decode(_fek))
local per = TLS_assert(b64decode(_per))

print(#fek)
dump(per)
