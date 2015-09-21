#include "objects/TimingDelayContext.hpp"

namespace luambedtls {
	mbedtls_timing_delay_context * TimingDelayContext::constructor(State & state, bool & managed){
		mbedtls_timing_delay_context * context = new mbedtls_timing_delay_context;
		return context;
	}

	void TimingDelayContext::destructor(State & state, mbedtls_timing_delay_context * context){
		delete context;
	}

	void initTimingDelayContext(State * state, Module & module){
		INIT_OBJECT(TimingDelayContext);
	}
};
