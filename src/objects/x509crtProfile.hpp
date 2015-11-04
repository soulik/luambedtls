#ifndef LUA_MBEDTLS_OBJECTS_X509CRTPROFILE_H
#define LUA_MBEDTLS_OBJECTS_X509CRTPROFILE_H

#include "common.hpp"

namespace luambedtls {
	class x509crtProfile : public Object<mbedtls_x509_crt_profile> {
	public:
		explicit x509crtProfile(State * state) : Object<mbedtls_x509_crt_profile>(state){
			LUTOK_PROPERTY("allowedMDs", &x509crtProfile::getAllowedMDs, &x509crtProfile::nullMethod);
			LUTOK_PROPERTY("allowedPKs", &x509crtProfile::getAllowedPKs, &x509crtProfile::nullMethod);
			LUTOK_PROPERTY("allowesCurves", &x509crtProfile::getAllowedCurves, &x509crtProfile::nullMethod);
			LUTOK_PROPERTY("RSAMinBitlen", &x509crtProfile::getRSAMinBitlen, &x509crtProfile::nullMethod);
		}

		mbedtls_x509_crt_profile * constructor(State & state, bool & managed);

		void destructor(State & state, mbedtls_x509_crt_profile * profile);

		int getAllowedMDs(State & state, mbedtls_x509_crt_profile * profile);
		int getAllowedPKs(State & state, mbedtls_x509_crt_profile * profile);
		int getAllowedCurves(State & state, mbedtls_x509_crt_profile * profile);
		int getRSAMinBitlen(State & state, mbedtls_x509_crt_profile * profile);
	};
	void initx509crtProfile(State*, Module&);
};
#endif	
