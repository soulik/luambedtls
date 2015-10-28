#include "objects/SSLCookieContext.hpp"
#include "objects/MDContext.hpp"
#include "objects/CTRDRBGContext.hpp"

namespace luambedtls {
	mbedtls_ssl_cookie_ctx * SSLCookieContext::constructor(State & state, bool & managed){
		mbedtls_ssl_cookie_ctx * context = new mbedtls_ssl_cookie_ctx;
		mbedtls_ssl_cookie_init(context);
		return context;
	}

	void SSLCookieContext::destructor(State & state, mbedtls_ssl_cookie_ctx * context){
		mbedtls_ssl_cookie_free(context);
		delete context;
	}

	int SSLCookieContext::getHMACContext(State & state, mbedtls_ssl_cookie_ctx * context){
		Stack * stack = state.stack;
		MDContext * interfaceMD = OBJECT_IFACE(MDContext);
		interfaceMD->push(&context->hmac_ctx);
		return 1;
	}
	int SSLCookieContext::getTimeout(State & state, mbedtls_ssl_cookie_ctx * context){
		Stack * stack = state.stack;
		stack->push<int>(context->timeout);
		return 1;
	}
	int SSLCookieContext::setHMACContext(State & state, mbedtls_ssl_cookie_ctx * context){
		Stack * stack = state.stack;
		MDContext * interfaceMD = OBJECT_IFACE(MDContext);
		mbedtls_md_context_t * src = interfaceMD->get(1);
		if (src){
			mbedtls_md_clone(&context->hmac_ctx, src);
		}
		return 0;
	}
	int SSLCookieContext::setTimeout(State & state, mbedtls_ssl_cookie_ctx * context){
		Stack * stack = state.stack;
		if (stack->is<LUA_TNUMBER>(1)){
			mbedtls_ssl_cookie_set_timeout(context, stack->to<int>(1));
		}
		return 0;
	}

	int SSLCookieContext::setup(State & state, mbedtls_ssl_cookie_ctx * context){
		Stack * stack = state.stack;
		CTRDRBGContext * interfaceCTRDRBGContext = OBJECT_IFACE(CTRDRBGContext);
		mbedtls_ctr_drbg_context * drbg = interfaceCTRDRBGContext->get(1);
		if (drbg){
			stack->push<int>(mbedtls_ssl_cookie_setup(context, mbedtls_ctr_drbg_random, drbg));
			return 1;
		}
		return 0;
	}

	

	void initSSLCookieContext(State * state, Module & module){
		INIT_OBJECT(SSLCookieContext);
	}
};
