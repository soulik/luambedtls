#ifndef LUA_MBEDTLS_OBJECTS_X509CRTPROFILE_H
#define LUA_MBEDTLS_OBJECTS_X509CRTPROFILE_H

#include "common.hpp"

namespace luambedtls {
	class x509crtProfile : public Object<mbedtls_x509_crt_profile> {
	public:
		explicit x509crtProfile(State * state) : Object<mbedtls_x509_crt_profile>(state){
		}

		mbedtls_x509_crt_profile * constructor(State & state, bool & managed);

		void destructor(State & state, mbedtls_x509_crt_profile * object);
	};
};

#endif	
