#ifndef LUA_MBEDTLS_OBJECTS_X509CSR_H
#define LUA_MBEDTLS_OBJECTS_X509CSR_H

#include "common.hpp"

namespace luambedtls {
	class x509csr : public Object<mbedtls_x509_csr> {
	public:
		explicit x509csr(State * state) : Object<mbedtls_x509_csr>(state){
			LUTOK_METHOD("parse", &x509csr::parse);
			LUTOK_METHOD("parseDER", &x509csr::parseDER);
			LUTOK_METHOD("parseFile", &x509csr::parseFile);
			LUTOK_METHOD("info", &x509csr::info);
		}

		mbedtls_x509_csr * constructor(State & state, bool & managed);

		void destructor(State & state, mbedtls_x509_csr * request);

		int parse(State & state, mbedtls_x509_csr * request);
		int parseDER(State & state, mbedtls_x509_csr * request);
		int parseFile(State & state, mbedtls_x509_csr * request);
		int info(State & state, mbedtls_x509_csr * request);
	};
};

#endif	
