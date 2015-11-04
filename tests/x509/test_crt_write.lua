#!/usr/bin/luajit

local bit = require 'bit'
local tls = require 'luambedtls'
local crtWrite = require 'crt_write'

crtWrite.create {
	issuerCrt = false,
	crtRequest = false,
	subjectKey = false,
	issuerKey = 'subject.key',
	subjectPwd = false,
	issuerPwd = false,
	output = 'subject.crt',
	subjectName = 'CN=Cert,O=mbed TLS,C=UK',
	issuerName = 'CN=CA,O=mbed TLS,C=UK',
	notBefore = '20010101000000',
	notAfter = '20301231235959',
	serial = '2',
	selfSign = true,
	isCA = false,
	maxPathLen = 0,
	--keyUsage = bit.bor(tls.X509_KU_DIGITAL_SIGNATURE, tls.X509_KU_KEY_ENCIPHERMENT, tls.X509_KU_DATA_ENCIPHERMENT, tls.X509_KU_KEY_AGREEMENT, tls.X509_KU_KEY_CERT_SIGN, tls.X509_KU_CRL_SIGN),
	keyUsage = bit.bor(tls.X509_KU_KEY_CERT_SIGN, tls.X509_KU_CRL_SIGN),
	--NSCertType = bit.bor(tls.X509_NS_CERT_TYPE_SSL_CLIENT, tls.X509_NS_CERT_TYPE_SSL_SERVER, tls.X509_NS_CERT_TYPE_EMAIL, tls.X509_NS_CERT_TYPE_OBJECT_SIGNING),
	NSCertType = false,
}

