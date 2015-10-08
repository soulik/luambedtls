#ifndef LUA_MBEDTLS_OBJECTS_ECSDACONTEXT_H
#define LUA_MBEDTLS_OBJECTS_ECSDACONTEXT_H

#include "common.hpp"

namespace luambedtls {
	class ECSDAContext : public Object<mbedtls_ecdsa_context> {
	public:
		explicit ECSDAContext(State * state) : Object<mbedtls_ecdsa_context>(state){
		}

		mbedtls_ecdsa_context * constructor(State & state, bool & managed);

		void destructor(State & state, mbedtls_ecdsa_context * context);
	};
};

#endif	
