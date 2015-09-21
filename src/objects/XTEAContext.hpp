#ifndef LUA_MBEDTLS_OBJECTS_XTEACONTEXT_H
#define LUA_MBEDTLS_OBJECTS_XTEACONTEXT_H

#include "common.hpp"

namespace luambedtls {
	class XTEAContext : public Object<mbedtls_xtea_context> {
	public:
		explicit XTEAContext(State * state) : Object<mbedtls_xtea_context>(state){
			LUTOK_METHOD("setup", &XTEAContext::setup);
			LUTOK_METHOD("cryptECB", &XTEAContext::cryptECB);
			LUTOK_METHOD("cryptCBC", &XTEAContext::cryptCBC);
		}

		mbedtls_xtea_context * constructor(State & state, bool & managed);

		void destructor(State & state, mbedtls_xtea_context * context);

		int setup(State & state, mbedtls_xtea_context * context);
		int cryptECB(State & state, mbedtls_xtea_context * context);
		int cryptCBC(State & state, mbedtls_xtea_context * context);
	};
};

#endif	
