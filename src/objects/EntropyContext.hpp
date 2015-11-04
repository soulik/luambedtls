#ifndef LUA_MBEDTLS_OBJECTS_ENTROPYCONTEXT_H
#define LUA_MBEDTLS_OBJECTS_ENTROPYCONTEXT_H

#include "common.hpp"

namespace luambedtls {
	class EntropyContext : public Object<mbedtls_entropy_context> {
	public:
		explicit EntropyContext(State * state) : Object<mbedtls_entropy_context>(state){
			LUTOK_METHOD("gather", &EntropyContext::gather);
			LUTOK_METHOD("updateManual", &EntropyContext::updateManual);
			LUTOK_METHOD("writeSeedFile", &EntropyContext::writeSeedFile);
			LUTOK_METHOD("updateFromSeedFile", &EntropyContext::updateFromSeedFile);
		}

		mbedtls_entropy_context * constructor(State & state, bool & managed);

		void destructor(State & state, mbedtls_entropy_context * object);

		int gather(State & state, mbedtls_entropy_context * object);
		int updateManual(State & state, mbedtls_entropy_context * object);
		int writeSeedFile(State & state, mbedtls_entropy_context * object);
		int updateFromSeedFile(State & state, mbedtls_entropy_context * object);
	};
	void initEntropyContext(State*, Module&);
};
#endif	
