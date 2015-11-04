#ifndef LUA_MBEDTLS_OBJECTS_DESCONTEXT_H
#define LUA_MBEDTLS_OBJECTS_DESCONTEXT_H

#include "common.hpp"

namespace luambedtls {
	class DESContext : public Object<mbedtls_des_context> {
	public:
		explicit DESContext(State * state) : Object<mbedtls_des_context>(state){
			LUTOK_METHOD("setKeyEnc", &DESContext::setKeyEnc);
			LUTOK_METHOD("setKeyDec", &DESContext::setKeyDec);
			LUTOK_METHOD("encryptECB", &DESContext::encryptECB);
			LUTOK_METHOD("encryptCBC", &DESContext::encryptCBC);
		}

		mbedtls_des_context * constructor(State & state, bool & managed);

		void destructor(State & state, mbedtls_des_context * object);
		
		int setKeyEnc(State & state, mbedtls_des_context * context);
		int setKeyDec(State & state, mbedtls_des_context * context);
		int encryptECB(State & state, mbedtls_des_context * context);
		int encryptCBC(State & state, mbedtls_des_context * context);

	};
	void initDESContext(State*, Module&);
	int DESSelfTest(State&);
	
	int DESSetKey(State &);
	int DESSetKeyParity(State &);
	int DESCheckKeyParity(State &);
	int DESKeyCheckWeak(State &);
};
#endif	
