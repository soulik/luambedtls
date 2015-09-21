#ifndef LUA_MBEDTLS_OBJECTS_ARC4CONTEXT_H
#define LUA_MBEDTLS_OBJECTS_ARC4CONTEXT_H

#include "common.hpp"

namespace luambedtls {
	class ARC4Context : public Object<mbedtls_arc4_context> {
	public:
		explicit ARC4Context(State * state) : Object<mbedtls_arc4_context>(state){
			LUTOK_METHOD("setup", &ARC4Context::setup);
			LUTOK_METHOD("crypt", &ARC4Context::crypt);
		}

		mbedtls_arc4_context * constructor(State & state, bool & managed);

		void destructor(State & state, mbedtls_arc4_context * object);

		int setup(State & state, mbedtls_arc4_context * context);
		int crypt(State & state, mbedtls_arc4_context * context);
	};
};

#endif	
