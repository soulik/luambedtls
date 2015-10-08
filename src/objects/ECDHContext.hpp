#ifndef LUA_MBEDTLS_OBJECTS_ECDHCONTEXT_H
#define LUA_MBEDTLS_OBJECTS_ECDHCONTEXT_H

#include "common.hpp"

namespace luambedtls {
	class ECDHContext : public Object<mbedtls_ecdh_context> {
	public:
		explicit ECDHContext(State * state) : Object<mbedtls_ecdh_context>(state){
		}

		mbedtls_ecdh_context * constructor(State & state, bool & managed);

		void destructor(State & state, mbedtls_ecdh_context * context);
	};
};

#endif	
