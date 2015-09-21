#ifndef LUA_MBEDTLS_OBJECTS_X509CRL_H
#define LUA_MBEDTLS_OBJECTS_X509CRL_H

#include "common.hpp"

namespace luambedtls {
	class x509crl : public Object<mbedtls_x509_crl> {
	public:
		explicit x509crl(State * state) : Object<mbedtls_x509_crl>(state){
			LUTOK_METHOD("parse", &x509crl::parse);
			LUTOK_METHOD("parseDER", &x509crl::parseDER);
			LUTOK_METHOD("parseFile", &x509crl::parseFile);
			LUTOK_METHOD("info", &x509crl::info);
		}

		mbedtls_x509_crl * constructor(State & state, bool & managed);

		void destructor(State & state, mbedtls_x509_crl * certificate);

		int parse(State & state, mbedtls_x509_crl * certificate);
		int parseDER(State & state, mbedtls_x509_crl * certificate);
		int parseFile(State & state, mbedtls_x509_crl * certificate);
		int info(State & state, mbedtls_x509_crl * certificate);
	};
};

#endif	
