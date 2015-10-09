#ifndef LUA_MBEDTLS_OBJECTS_ECDHCONTEXT_H
#define LUA_MBEDTLS_OBJECTS_ECDHCONTEXT_H

#include "common.hpp"

namespace luambedtls {
	class ECDHContext : public Object<mbedtls_ecdh_context> {
	public:
		explicit ECDHContext(State * state) : Object<mbedtls_ecdh_context>(state){
			LUTOK_METHOD("genPublic", &ECDHContext::genPublic);
			LUTOK_METHOD("computeShared", &ECDHContext::computeShared);
			LUTOK_METHOD("makeParams", &ECDHContext::makeParams);
			LUTOK_METHOD("readParams", &ECDHContext::readParams);
			LUTOK_METHOD("getParams", &ECDHContext::getParams);
			LUTOK_METHOD("makePublic", &ECDHContext::makePublic);
			LUTOK_METHOD("readPublic", &ECDHContext::readPublic);
			LUTOK_METHOD("calcSecret", &ECDHContext::calcSecret);
		}

		mbedtls_ecdh_context * constructor(State & state, bool & managed);

		void destructor(State & state, mbedtls_ecdh_context * context);

		int genPublic(State & state, mbedtls_ecdh_context * context);
		int computeShared(State & state, mbedtls_ecdh_context * context);
		int makeParams(State & state, mbedtls_ecdh_context * context);
		int readParams(State & state, mbedtls_ecdh_context * context);
		int getParams(State & state, mbedtls_ecdh_context * context);
		int makePublic(State & state, mbedtls_ecdh_context * context);
		int readPublic(State & state, mbedtls_ecdh_context * context);
		int calcSecret(State & state, mbedtls_ecdh_context * context);
	};
};

#endif	
