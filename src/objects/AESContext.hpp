#ifndef LUA_MBEDTLS_OBJECTS_AESCONTEXT_H
#define LUA_MBEDTLS_OBJECTS_AESCONTEXT_H

#include "common.hpp"

namespace luambedtls {
	class AESContext : public Object<mbedtls_aes_context> {
	public:
		explicit AESContext(State * state) : Object<mbedtls_aes_context>(state){
			LUTOK_METHOD("setKeyEnc", &AESContext::setKeyEnc);
			LUTOK_METHOD("setKeyDec", &AESContext::setKeyDec);
			LUTOK_METHOD("cryptECB", &AESContext::cryptECB);
			LUTOK_METHOD("cryptCBC", &AESContext::cryptCBC);
			LUTOK_METHOD("cryptCFB128", &AESContext::cryptCFB128);
			LUTOK_METHOD("cryptCFB8", &AESContext::cryptCFB8);
			LUTOK_METHOD("cryptCTR", &AESContext::cryptCTR);
			LUTOK_METHOD("encrypt", &AESContext::encrypt);
			LUTOK_METHOD("decrypt", &AESContext::decrypt);
		}

		mbedtls_aes_context * constructor(State & state, bool & managed);

		void destructor(State & state, mbedtls_aes_context * context);

		int setKeyEnc(State & state, mbedtls_aes_context * context);
		int setKeyDec(State & state, mbedtls_aes_context * context);
		int cryptECB(State & state, mbedtls_aes_context * context);
		int cryptCBC(State & state, mbedtls_aes_context * context);
		int cryptCFB128(State & state, mbedtls_aes_context * context);
		int cryptCFB8(State & state, mbedtls_aes_context * context);
		int cryptCTR(State & state, mbedtls_aes_context * context);
		int encrypt(State & state, mbedtls_aes_context * context);
		int decrypt(State & state, mbedtls_aes_context * context);
	};
	void initAESContext(State*, Module&);
	int AESSelfTest(State&);
};
#endif	
