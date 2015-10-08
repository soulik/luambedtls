#include "objects/ECDHContext.hpp"

namespace luambedtls {
	mbedtls_ecdh_context * ECDHContext::constructor(State & state, bool & managed){
		mbedtls_ecdh_context * context = new mbedtls_ecdh_context;
		mbedtls_ecdh_init(context);
		return context;
	}

	void ECDHContext::destructor(State & state, mbedtls_ecdh_context * context){
		mbedtls_ecdh_free(context);
		delete context;
	}

	void initECDHContext(State * state, Module & module){
		INIT_OBJECT(ECDHContext);
	}
};
