#include "objects/SSLSession.hpp"

namespace luambedtls {
	mbedtls_ssl_session * SSLSession::constructor(State & state, bool & managed){
		Stack * stack = state.stack;
		mbedtls_ssl_session * session = new mbedtls_ssl_session;

		mbedtls_ssl_session_init(session);
		return session;
	}

	void SSLSession::destructor(State & state, mbedtls_ssl_session * session){
		mbedtls_ssl_session_free(session);
		delete session;
	}

	void initSSLSession(State * state, Module & module){
		INIT_OBJECT(SSLSession);
	}
};
