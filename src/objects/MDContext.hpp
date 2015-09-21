#ifndef LUA_MBEDTLS_OBJECTS_MDCONTEXT_H
#define LUA_MBEDTLS_OBJECTS_MDCONTEXT_H

#include "common.hpp"

namespace luambedtls {
	class MDContext : public Object<mbedtls_md_context_t> {
	public:
		explicit MDContext(State * state) : Object<mbedtls_md_context_t>(state){
		}

		mbedtls_md_context_t * constructor(State & state, bool & managed);

		void destructor(State & state, mbedtls_md_context_t * object);
	};
};

#endif	
