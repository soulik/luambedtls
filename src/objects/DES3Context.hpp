#ifndef LUA_MBEDTLS_OBJECTS_DES3CONTEXT_H
#define LUA_MBEDTLS_OBJECTS_DES3CONTEXT_H

#include "common.hpp"

namespace luambedtls {
	class DES3Context : public Object<mbedtls_des3_context> {
	public:
		explicit DES3Context(State * state) : Object<mbedtls_des3_context>(state){
			LUTOK_METHOD("set2KeyEnc", &DES3Context::set2KeyEnc);
			LUTOK_METHOD("set2KeyDec", &DES3Context::set2KeyDec);
			LUTOK_METHOD("set3KeyEnc", &DES3Context::set3KeyEnc);
			LUTOK_METHOD("set3KeyDec", &DES3Context::set3KeyDec);
			LUTOK_METHOD("encryptECB", &DES3Context::encryptECB);
			LUTOK_METHOD("encryptCBC", &DES3Context::encryptCBC);
		}

		mbedtls_des3_context * constructor(State & state, bool & managed);

		void destructor(State & state, mbedtls_des3_context * object);

		int set2KeyEnc(State & state, mbedtls_des3_context * context);
		int set2KeyDec(State & state, mbedtls_des3_context * context);
		int set3KeyEnc(State & state, mbedtls_des3_context * context);
		int set3KeyDec(State & state, mbedtls_des3_context * context);
		int encryptECB(State & state, mbedtls_des3_context * context);
		int encryptCBC(State & state, mbedtls_des3_context * context);
	};
	void initDES3Context(State*, Module&);
};
#endif	
