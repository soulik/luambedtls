local tls = require 'luambedtls'
local tls_utils = require 'tls_utils'
require 'utils'
local setupGCdependencies, tlsAssert = tls_utils.setupGCdependencies, tls_utils.tlsAssert

local entropy = tls.EntropyContext()
local CTR_DRBG = tls.CTRDRBGContext()
local ssl = tls.SSLContext()
local sslConfig
local CAcert = tls.x509crt()
local timer = tls.TimingDelayContext()

local PEMdata = [[]]
local MESSAGE = [[
Hello
]]

local function send(msg)
	--print(msg:hex_dump{prefix="\nSend - "})
	return #msg
end

local function recv(len)
	local msg = ':)'
	--print('Recv', len)
	return #msg, msg
end

local function recvTimeout(len, timeout)
	local msg = ':)'
	--print('RecvTimeout', len, timeout)
	return #msg, msg
end


printf("\n  . Seeding the random number generator...")
tlsAssert(CTR_DRBG.seed(entropy, "sslclient"))
printf("ok\n")

printf( "  . Loading the CA root certificate ..." )
local ret = tlsAssert(CAcert.parse())
printf( " ok (%d skipped)\n", ret )

print(CAcert.info(1024))

-- connect

printf( "  . Setting up the DTLS structure..." );
sslConfig = tls.SSLConfig(tls.SSL_IS_CLIENT, tls.SSL_TRANSPORT_STREAM, tls.SSL_PRESET_DEFAULT)
tlsAssert(sslConfig)

setupGCdependencies(ssl, sslConfig)

sslConfig.authmode = tls.SSL_VERIFY_OPTIONAL
sslConfig.setCAChain(CAcert)
sslConfig.setRNG(CTR_DRBG)

sslConfig.setDBG(true)
tls.debugTreshhold(0)

tlsAssert(ssl.setup(sslConfig))
tlsAssert(ssl.setHostname("localhost"))

ssl.setBIO(send, recv, recvTimeout)
ssl.setTimer(timer)

--[[
    mbedtls_ssl_set_bio( &ssl, &server_fd, mbedtls_net_send, mbedtls_net_recv, mbedtls_net_recv_timeout );
    mbedtls_ssl_set_timer_cb( &ssl, &timer, mbedtls_timing_set_delay, mbedtls_timing_get_delay );
--]]
printf( " ok\n" )
printf( "  . Performing the SSL/TLS handshake..." )

local ret = 0

repeat
	ret = ssl.handshake()
until (ret ~= tls.ERR_SSL_WANT_READ and ret ~= tls.ERR_SSL_WANT_WRITE)

print(ret)
tlsAssert(ret)

printf( " ok\n" )

printf( "  . Verifying peer X.509 certificate..." )
tlsAssert(ssl.verifyResult)
printf( " ok\n" )

printf( "  > Write to server:" )

repeat
	ret = ssl.write(MESSAGE)
until (ret ~= tls.ERR_SSL_WANT_READ and ret ~= tls.ERR_SSL_WANT_WRITE)

tlsAssert(ret)
printf( " %d bytes written\n\n%s\n\n", ret, MESSAGE )

printf( "  < Read from server:" )
local ret, str

repeat
	ret, str = ssl.read(1024)
until (ret ~= tls.ERR_SSL_WANT_READ and ret ~= tls.ERR_SSL_WANT_WRITE)

if (ret <= 0) then
	if ret == tls.ERR_SSL_TIMEOUT then
		printf( " timeout\n\n" )
	elseif ret == tls.ERR_SSL_PEER_CLOSE_NOTIFY then
		printf( " connection was closed gracefully\n" )
	else
		error('read error')
	end
end
printf( " %d bytes read\n\n%s\n\n", ret, buf )

printf( "  . Closing the connection..." )

repeat
	ret = ssl.closeNotify()
until (ret ~= tls.ERR_SSL_WANT_WRITE)

printf( " done\n" )
