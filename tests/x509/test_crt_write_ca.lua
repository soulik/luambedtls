local bit = require 'bit'
local tls = require 'luambedtls'
local crtWrite = require 'crt_write'

crtWrite.create {
	issuerCrt = false,
	crtRequest = false,
	subjectKey = false,
	issuerKey = 'CA.key',
	subjectPwd = false,
	issuerPwd = false,
	output = 'CA.crt',
	subjectName = 'CN=CA,O=mbed TLS,C=UK',
	issuerName = 'CN=CA,O=mbed TLS,C=UK',
	notBefore = '20010101000000',
	notAfter = '20301231235959',
	serial = '1',
	selfSign = true,
	isCA = true,
	maxPathLen = -1,
	--keyUsage = bit.bor(tls.X509_KU_DIGITAL_SIGNATURE, tls.X509_KU_KEY_ENCIPHERMENT, tls.X509_KU_DATA_ENCIPHERMENT, tls.X509_KU_KEY_AGREEMENT, tls.X509_KU_KEY_CERT_SIGN, tls.X509_KU_CRL_SIGN),
	keyUsage = false,
	--NSCertType = bit.bor(tls.X509_NS_CERT_TYPE_SSL_CLIENT, tls.X509_NS_CERT_TYPE_SSL_SERVER, tls.X509_NS_CERT_TYPE_EMAIL, tls.X509_NS_CERT_TYPE_OBJECT_SIGNING, tls.X509_NS_CERT_TYPE_SSL_CA, tls.X509_NS_CERT_TYPE_EMAIL_CA, tls.X509_NS_CERT_TYPE_OBJECT_SIGNING_CA),
	NSCertType = false,
}