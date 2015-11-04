#ifndef LUA_MBEDTLS_OBJECTS_SSLSESSION_H
#define LUA_MBEDTLS_OBJECTS_SSLSESSION_H

#include "common.hpp"

namespace luambedtls {
	class SSLSession : public Object<mbedtls_ssl_session> {
	public:
		explicit SSLSession(State * state) : Object<mbedtls_ssl_session>(state){
			LUTOK_PROPERTY("start", &SSLSession::getStart, &SSLSession::nullMethod);
			LUTOK_PROPERTY("cipherSuite", &SSLSession::getCipherSuite, &SSLSession::nullMethod);
			LUTOK_PROPERTY("compression", &SSLSession::getCompression, &SSLSession::nullMethod);
			LUTOK_PROPERTY("ID", &SSLSession::getID, &SSLSession::nullMethod);
			LUTOK_PROPERTY("master", &SSLSession::getMaster, &SSLSession::nullMethod);
			LUTOK_PROPERTY("peerCert", &SSLSession::getPeerCert, &SSLSession::nullMethod);
			LUTOK_PROPERTY("verifyResult", &SSLSession::getVerifyResult, &SSLSession::nullMethod);
			LUTOK_PROPERTY("ticket", &SSLSession::getTicket, &SSLSession::nullMethod);
			LUTOK_PROPERTY("ticketLifetime", &SSLSession::getTicketLifetime, &SSLSession::nullMethod);
			LUTOK_PROPERTY("MFLCode", &SSLSession::getMFLCode, &SSLSession::nullMethod);
			LUTOK_PROPERTY("truncHMAC", &SSLSession::getTruncHMAC, &SSLSession::nullMethod);
			LUTOK_PROPERTY("encryptThenHMAC", &SSLSession::getEncryptThenMAC, &SSLSession::nullMethod);
		}

		mbedtls_ssl_session * constructor(State & state, bool & managed);

		void destructor(State & state, mbedtls_ssl_session * session);

		int getStart(State & state, mbedtls_ssl_session * session);
		int getCipherSuite(State & state, mbedtls_ssl_session * session);
		int getCompression(State & state, mbedtls_ssl_session * session);
		int getID(State & state, mbedtls_ssl_session * session);
		int getMaster(State & state, mbedtls_ssl_session * session);
		int getPeerCert(State & state, mbedtls_ssl_session * session);
		int getVerifyResult(State & state, mbedtls_ssl_session * session);
		int getTicket(State & state, mbedtls_ssl_session * session);
		int getTicketLifetime(State & state, mbedtls_ssl_session * session);
		int getMFLCode(State & state, mbedtls_ssl_session * session);
		int getTruncHMAC(State & state, mbedtls_ssl_session * session);
		int getEncryptThenMAC(State & state, mbedtls_ssl_session * session);
	};
};

#endif	
