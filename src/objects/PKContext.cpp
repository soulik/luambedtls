#include "objects/PKContext.hpp"
#include "objects/RSAContext.hpp"

namespace luambedtls {
	mbedtls_pk_context * PKContext::constructor(State & state, bool & managed){
		mbedtls_pk_context * context = new mbedtls_pk_context;
		mbedtls_pk_init(context);
		return context;
	}

	void PKContext::destructor(State & state, mbedtls_pk_context * context){
		mbedtls_pk_free(context);
		delete context;
	}

	int PKContext::getRSA(State & state, mbedtls_pk_context * context){
		Stack * stack = state.stack;
		RSAContext * interfaceRSA = OBJECT_IFACE(RSAContext);
		mbedtls_rsa_context * rsa = mbedtls_pk_rsa(*context);
		if (rsa){
			interfaceRSA->push(rsa);
			return 1;
		}
		else{
			return 0;
		}
	}

	int PKContext::getType(State & state, mbedtls_pk_context * context){
		Stack * stack = state.stack;
		stack->push<int>(context->pk_info->type);
		return 1;
	}
	int PKContext::getName(State & state, mbedtls_pk_context * context){
		Stack * stack = state.stack;
		stack->push<const std::string &>(context->pk_info->name);
		return 1;
	}
	int PKContext::getBitLen(State & state, mbedtls_pk_context * context){
		Stack * stack = state.stack;
		stack->push<int>(context->pk_info->get_bitlen(context->pk_ctx));
		return 1;
	}

	


	void initPKContext(State * state, Module & module){
		INIT_OBJECT(PKContext);
	}
};
