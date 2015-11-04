#ifndef LUA_MBEDTLS_OBJECTS_CAMELLIACONTEXT_H
#define LUA_MBEDTLS_OBJECTS_CAMELLIACONTEXT_H

#include "common.hpp"

namespace luambedtls {
	class CamelliaContext : public Object<mbedtls_camellia_context> {
	public:
		explicit CamelliaContext(State * state) : Object<mbedtls_camellia_context>(state){
			LUTOK_METHOD("setKeyEnc", &CamelliaContext::setKeyEnc);
			LUTOK_METHOD("setKeyDec", &CamelliaContext::setKeyDec);
			LUTOK_METHOD("cryptECB", &CamelliaContext::cryptECB);
			LUTOK_METHOD("cryptCBC", &CamelliaContext::cryptCBC);
			LUTOK_METHOD("cryptCFB128", &CamelliaContext::cryptCFB128);
			LUTOK_METHOD("cryptCTR", &CamelliaContext::cryptCTR);
		}

		mbedtls_camellia_context * constructor(State & state, bool & managed);

		void destructor(State & state, mbedtls_camellia_context * object);

		int setKeyEnc(State & state, mbedtls_camellia_context * context);
		int setKeyDec(State & state, mbedtls_camellia_context * context);
		int cryptECB(State & state, mbedtls_camellia_context * context);
		int cryptCBC(State & state, mbedtls_camellia_context * context);
		int cryptCFB128(State & state, mbedtls_camellia_context * context);
		int cryptCTR(State & state, mbedtls_camellia_context * context);
	};
	void initCamelliaContext(State*, Module&);
	int CamelliaSelfTest(State&);
};
#endif	
