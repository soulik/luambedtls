#ifndef LUA_MBEDTLS_OBJECTS_BLOWFISHCONTEXT_H
#define LUA_MBEDTLS_OBJECTS_BLOWFISHCONTEXT_H

#include "common.hpp"

namespace luambedtls {
	class BlowfishContext : public Object<mbedtls_blowfish_context> {
	public:
		explicit BlowfishContext(State * state) : Object<mbedtls_blowfish_context>(state){
			LUTOK_METHOD("setKey", &BlowfishContext::setKey);
			LUTOK_METHOD("cryptECB", &BlowfishContext::cryptECB);
			LUTOK_METHOD("cryptCBC", &BlowfishContext::cryptCBC);
			LUTOK_METHOD("cryptCFB64", &BlowfishContext::cryptCFB64);
			LUTOK_METHOD("cryptCTR", &BlowfishContext::cryptCTR);
		}

		mbedtls_blowfish_context * constructor(State & state, bool & managed);

		void destructor(State & state, mbedtls_blowfish_context * object);

		int setKey(State & state, mbedtls_blowfish_context * context);
		int cryptECB(State & state, mbedtls_blowfish_context * context);
		int cryptCBC(State & state, mbedtls_blowfish_context * context);
		int cryptCFB64(State & state, mbedtls_blowfish_context * context);
		int cryptCTR(State & state, mbedtls_blowfish_context * context);
	};
	void initBlowfishContext(State*, Module&);
};
#endif	
