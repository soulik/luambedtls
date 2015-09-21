#ifndef LUA_MBEDTLS_OBJECTS_TIMINGDELAYCONTEXT_H
#define LUA_MBEDTLS_OBJECTS_TIMINGDELAYCONTEXT_H

#include "common.hpp"

namespace luambedtls {
	class TimingDelayContext : public Object<mbedtls_timing_delay_context> {
	public:
		explicit TimingDelayContext(State * state) : Object<mbedtls_timing_delay_context>(state){
		}

		mbedtls_timing_delay_context * constructor(State & state, bool & managed);

		void destructor(State & state, mbedtls_timing_delay_context * object);
	};
};

#endif	
