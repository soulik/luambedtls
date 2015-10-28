#ifndef LUA_MBEDTLS_OBJECTS_SSLCOOKIECONTEXT_H
#define LUA_MBEDTLS_OBJECTS_SSLCOOKIECONTEXT_H

#include "common.hpp"

namespace luambedtls {
	class SSLCookieContext : public Object<mbedtls_ssl_cookie_ctx> {
	public:
		explicit SSLCookieContext(State * state) : Object<mbedtls_ssl_cookie_ctx>(state){
			LUTOK_PROPERTY("HMACContext", &SSLCookieContext::getHMACContext, &SSLCookieContext::setHMACContext);
			LUTOK_PROPERTY("timeout", &SSLCookieContext::getTimeout, &SSLCookieContext::setTimeout);
			LUTOK_METHOD("setup", &SSLCookieContext::setup);
		}

		mbedtls_ssl_cookie_ctx * constructor(State & state, bool & managed);

		void destructor(State & state, mbedtls_ssl_cookie_ctx * context);

		int getHMACContext(State & state, mbedtls_ssl_cookie_ctx * context);
		int getTimeout(State & state, mbedtls_ssl_cookie_ctx * context);
		int setHMACContext(State & state, mbedtls_ssl_cookie_ctx * context);
		int setTimeout(State & state, mbedtls_ssl_cookie_ctx * context);

		int setup(State & state, mbedtls_ssl_cookie_ctx * context);
	};
};

#endif	
