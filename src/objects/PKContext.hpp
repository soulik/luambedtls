#ifndef LUA_MBEDTLS_OBJECTS_PKCONTEXT_H
#define LUA_MBEDTLS_OBJECTS_PKCONTEXT_H

#include "common.hpp"

namespace luambedtls {
	class PKContext : public Object<mbedtls_pk_context> {
	public:
		explicit PKContext(State * state) : Object<mbedtls_pk_context>(state){
			LUTOK_PROPERTY("rsa", &PKContext::getRSA, &PKContext::nullMethod);
			LUTOK_PROPERTY("type", &PKContext::getType, &PKContext::nullMethod);
			LUTOK_PROPERTY("name", &PKContext::getName, &PKContext::nullMethod);
			LUTOK_PROPERTY("bitLen", &PKContext::getBitLen, &PKContext::nullMethod);
		}

		mbedtls_pk_context * constructor(State & state, bool & managed);

		void destructor(State & state, mbedtls_pk_context * context);
		
		int getRSA(State & state, mbedtls_pk_context * context);
		int getType(State & state, mbedtls_pk_context * context);
		int getName(State & state, mbedtls_pk_context * context);
		int getBitLen(State & state, mbedtls_pk_context * context);
	};
};

#endif	
