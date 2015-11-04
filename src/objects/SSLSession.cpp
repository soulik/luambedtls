#include "objects/SSLSession.hpp"
#include "objects/x509crt.hpp"

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

	int SSLSession::getStart(State & state, mbedtls_ssl_session * session){
		Stack * stack = state.stack;
#if defined(MBEDTLS_HAVE_TIME)
		stack->push<LUA_NUMBER>(session->start);
		return 1;
#else
		return 0;
#endif // MBEDTLS_HAVE_TIME

	}
	int SSLSession::getCipherSuite(State & state, mbedtls_ssl_session * session){
		Stack * stack = state.stack;
		stack->push<int>(session->ciphersuite);
		return 1;
	}
	int SSLSession::getCompression(State & state, mbedtls_ssl_session * session){
		Stack * stack = state.stack;
		stack->push<int>(session->compression);
		return 1;
	}
	int SSLSession::getID(State & state, mbedtls_ssl_session * session){
		Stack * stack = state.stack;
		stack->pushLString(std::string(reinterpret_cast<char*>(session->id), session->id_len));
		return 1;
	}
	int SSLSession::getMaster(State & state, mbedtls_ssl_session * session){
		Stack * stack = state.stack;
		stack->pushLString(std::string(reinterpret_cast<char*>(session->master), sizeof(session->master)));
		return 1;
	}
	int SSLSession::getPeerCert(State & state, mbedtls_ssl_session * session){
		Stack * stack = state.stack;
#if defined(MBEDTLS_X509_CRT_PARSE_C)
		x509crt * interfaceCrt = OBJECT_IFACE(x509crt);
		interfaceCrt->push(session->peer_cert);
		return 1;
#else
		return 0;
#endif // MBEDTLS_X509_CRT_PARSE_C
	}
	int SSLSession::getVerifyResult(State & state, mbedtls_ssl_session * session){
		Stack * stack = state.stack;
		stack->push<int>(session->verify_result);
		return 1;
	}
	int SSLSession::getTicket(State & state, mbedtls_ssl_session * session){
		Stack * stack = state.stack;
#if defined(MBEDTLS_SSL_SESSION_TICKETS) && defined(MBEDTLS_SSL_CLI_C)
		stack->pushLString(std::string(reinterpret_cast<char*>(session->ticket), session->ticket_len));
		return 1;
#else
		return 0;
#endif
	}
	int SSLSession::getTicketLifetime(State & state, mbedtls_ssl_session * session){
		Stack * stack = state.stack;
#if defined(MBEDTLS_SSL_SESSION_TICKETS) && defined(MBEDTLS_SSL_CLI_C)
		stack->push<LUA_NUMBER>(session->ticket_lifetime);
		return 1;
#else
		return 0;
#endif
	}
	int SSLSession::getMFLCode(State & state, mbedtls_ssl_session * session){
		Stack * stack = state.stack;
#if defined(MBEDTLS_SSL_MAX_FRAGMENT_LENGTH)
		stack->push<int>(session->mfl_code);
		return 1;
#else
		return 0;
#endif
	}
	int SSLSession::getTruncHMAC(State & state, mbedtls_ssl_session * session){
		Stack * stack = state.stack;
#if defined(MBEDTLS_SSL_TRUNCATED_HMAC)
		stack->push<int>(session->trunc_hmac);
		return 1;
#else
		return 0;
#endif
	}
	int SSLSession::getEncryptThenMAC(State & state, mbedtls_ssl_session * session){
		Stack * stack = state.stack;
#if defined(MBEDTLS_SSL_ENCRYPT_THEN_MAC)
		stack->push<int>(session->encrypt_then_mac);
		return 1;
#else
		return 0;
#endif
	}

	void initSSLSession(State * state, Module & module){
		INIT_OBJECT(SSLSession);
	}
};
