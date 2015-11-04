#ifndef LUA_MBEDTLS_OBJECTS_X509WRITECSR_H
#define LUA_MBEDTLS_OBJECTS_X509WRITECSR_H

#include "common.hpp"

namespace luambedtls {
	class x509writeCSR : public Object<mbedtls_x509write_csr> {
	public:
		explicit x509writeCSR(State * state) : Object<mbedtls_x509write_csr>(state){
			LUTOK_PROPERTY("key", &x509writeCSR::nullMethod, &x509writeCSR::setKey);
			LUTOK_PROPERTY("subject", &x509writeCSR::nullMethod, &x509writeCSR::setSubject);
			LUTOK_PROPERTY("MDAlg", &x509writeCSR::nullMethod, &x509writeCSR::setMDAlg);
			LUTOK_PROPERTY("NSCertType", &x509writeCSR::nullMethod, &x509writeCSR::setNSCertType);

			LUTOK_METHOD("extensions", &x509writeCSR::setExtensions);

			LUTOK_METHOD("writePEM", &x509writeCSR::writePEM);
			LUTOK_METHOD("writeDER", &x509writeCSR::writeDER);
		}

		mbedtls_x509write_csr * constructor(State & state, bool & managed);

		void destructor(State & state, mbedtls_x509write_csr * request);
		int setKey(State & state, mbedtls_x509write_csr * request);
		int setSubject(State & state, mbedtls_x509write_csr * request);
		int setMDAlg(State & state, mbedtls_x509write_csr * request);
		int setExtensions(State & state, mbedtls_x509write_csr * request);
		int setNSCertType(State & state, mbedtls_x509write_csr * request);

		int writePEM(State & state, mbedtls_x509write_csr * request);
		int writeDER(State & state, mbedtls_x509write_csr * request);
	};
	void initx509writeCSR(State*, Module&);
};
#endif	
