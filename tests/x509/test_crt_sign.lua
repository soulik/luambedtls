local bit = require 'bit'
local tls = require 'luambedtls'
local crtWrite = require 'crt_write'

crtWrite.create {
	issuerCrt = 'CA.crt',
	crtRequest = 'subject.csr',
	subjectKey = 'subject.key',
	issuerKey = 'CA.key',
	subjectPwd = false,
	issuerPwd = false,
	output = 'subject_signed.crt',
	subjectName = 'CN=Cert,O=mbed TLS,C=UK',
	issuerName = 'CN=CA,O=mbed TLS,C=UK',
	notBefore = '20010101000000',
	notAfter = '20301231235959',
	serial = '2',
	selfSign = false,
	isCA = false,
	maxPathLen = 0,
	keyUsage = bit.bor(tls.X509_KU_KEY_CERT_SIGN, tls.X509_KU_CRL_SIGN),
	NSCertType = false,
}