#ifndef LUA_MBEDTLS_OBJECTS_SSLSESSION_H
#define LUA_MBEDTLS_OBJECTS_SSLSESSION_H

#include "common.hpp"

namespace luambedtls {
	class SSLSession : public Object<mbedtls_ssl_session> {
	public:
		explicit SSLSession(State * state) : Object<mbedtls_ssl_session>(state){
		}

		mbedtls_ssl_session * constructor(State & state, bool & managed);

		void destructor(State & state, mbedtls_ssl_session * session);
	};
};

#endif	
