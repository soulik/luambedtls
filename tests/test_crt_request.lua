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

local options = {
	key = 'subject.key',
	password = false,
	output = 'subject.csr',
	subject = 'CN=Cert,O=mbed TLS,C=UK',
	keyUsage = bit.bor(tls.X509_KU_DIGITAL_SIGNATURE, tls.X509_KU_KEY_ENCIPHERMENT, tls.X509_KU_DATA_ENCIPHERMENT, tls.X509_KU_KEY_AGREEMENT, tls.X509_KU_KEY_CERT_SIGN, tls.X509_KU_CRL_SIGN),
	NSCertType = bit.bor(tls.X509_NS_CERT_TYPE_SSL_CLIENT, tls.X509_NS_CERT_TYPE_SSL_SERVER, tls.X509_NS_CERT_TYPE_EMAIL, tls.X509_NS_CERT_TYPE_OBJECT_SIGNING),
}

local entropy = tls.EntropyContext()
local CTR_DRBG = tls.CTRDRBGContext()
CTR_DRBG.seed(entropy, "gen_cert_request")

local csr = tls.x509writeCSR()
csr.MDAlg = tls.MD_SHA256
local pk = tls.PKContext()

csr.subject = options.subject
csr.keyUsage = options.keyUsage
csr.NSCertType = options.NSCertType

TLS_assert(pk.parseKeyFile(options.key, options.password))
csr.key = pk

local csrStr = TLS_assert(csr.writePEM(1024, CTR_DRBG))
csrStr = csrStr:sub(1,csrStr:find("\0"))

assert(io.open(options.output,'w')):write(csrStr):close()
