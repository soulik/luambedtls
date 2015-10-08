#include "objects/ECSDAContext.hpp"

namespace luambedtls {
	mbedtls_ecdsa_context * ECSDAContext::constructor(State & state, bool & managed){
		mbedtls_ecdsa_context * context = new mbedtls_ecdsa_context;
		mbedtls_ecdsa_init(context);
		return context;
	}

	void ECSDAContext::destructor(State & state, mbedtls_ecdsa_context * context){
		mbedtls_ecdsa_free(context);
		delete context;
	}

	void initECSDAContext(State * state, Module & module){
		INIT_OBJECT(ECSDAContext);
	}
};
