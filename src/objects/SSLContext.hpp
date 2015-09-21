#ifndef LUA_MBEDTLS_OBJECTS_SSLCONTEXT_H
#define LUA_MBEDTLS_OBJECTS_SSLCONTEXT_H

#include "common.hpp"

namespace luambedtls {
	struct SSLContextData {
		State * state;
		int recvRef;
		int recvTimeoutRef;
		int sendRef;
		mbedtls_ssl_context * context;
	};

	class SSLContext : public Object<SSLContextData> {
	public:
		explicit SSLContext(State * state) : Object<SSLContextData>(state){
			LUTOK_METHOD("setup", &SSLContext::setup);
			LUTOK_METHOD("sessionReset", &SSLContext::sessionReset);
			LUTOK_METHOD("setClientTransportID", &SSLContext::setClientTransportID);
			LUTOK_METHOD("setSession", &SSLContext::setSession);
			LUTOK_METHOD("setBIO", &SSLContext::setBIO);
			LUTOK_METHOD("setPSK", &SSLContext::setPSK);
			LUTOK_METHOD("setOwnCert", &SSLContext::setOwnCert);
			LUTOK_METHOD("setCAChain", &SSLContext::setCAChain);
			LUTOK_METHOD("setAuthmode", &SSLContext::setCAChain);
			LUTOK_METHOD("setTimer", &SSLContext::setTimer);
			LUTOK_METHOD("renegotiate", &SSLContext::renegotiate);
			LUTOK_METHOD("handshake", &SSLContext::handshake);
			LUTOK_METHOD("handshakeStep", &SSLContext::handshakeStep);
			LUTOK_METHOD("read", &SSLContext::read);
			LUTOK_METHOD("write", &SSLContext::write);
			LUTOK_METHOD("sendAlertMessage", &SSLContext::sendAlertMessage);
			LUTOK_METHOD("closeNotify", &SSLContext::closeNotify);

			LUTOK_METHOD("setHostname", &SSLContext::setHostname);
			LUTOK_PROPERTY("ALPNProtocol", &SSLContext::getALPNProtocol, &SSLContext::nullMethod);
			LUTOK_PROPERTY("bytesAvail", &SSLContext::getBytesAvail, &SSLContext::nullMethod);
			LUTOK_PROPERTY("verifyResult", &SSLContext::getVerifyResult, &SSLContext::nullMethod);
			LUTOK_PROPERTY("cipherSuite", &SSLContext::getCipherSuite, &SSLContext::nullMethod);
			LUTOK_PROPERTY("version", &SSLContext::getVersion, &SSLContext::nullMethod);
			LUTOK_PROPERTY("recordExpansion", &SSLContext::getRecordExpansion, &SSLContext::nullMethod);

			LUTOK_PROPERTY("peerCert", &SSLContext::getPeerCert, &SSLContext::nullMethod);
			LUTOK_PROPERTY("session", &SSLContext::getSession, &SSLContext::nullMethod);
		}

		SSLContextData * constructor(State & state, bool & managed);

		void destructor(State & state, SSLContextData * ssl_context);

		int setup(State & state, SSLContextData * ssl_context);
		int handshake(State & state, SSLContextData * ssl_context);
		int handshakeStep(State & state, SSLContextData * ssl_context);
		int renegotiate(State & state, SSLContextData * ssl_context);
		int read(State & state, SSLContextData * ssl_context);
		int write(State & state, SSLContextData * ssl_context);
		int sendAlertMessage(State & state, SSLContextData * ssl_context);
		int closeNotify(State & state, SSLContextData * ssl_context);

		int setBIO(State & state, SSLContextData * ssl_context);
		int setClientTransportID(State & state, SSLContextData * ssl_context);
		int setSession(State & state, SSLContextData * ssl_context);
		int setPSK(State & state, SSLContextData * ssl_context);
		int setHostname(State & state, SSLContextData * ssl_context);
		int setOwnCert(State & state, SSLContextData * ssl_context);
		int setCAChain(State & state, SSLContextData * ssl_context);
		int setAuthmode(State & state, SSLContextData * ssl_context);
		int setTimer(State & state, SSLContextData * ssl_context);

		int sessionReset(State & state, SSLContextData * ssl_context);

		int getALPNProtocol(State & state, SSLContextData * ssl_context);
		int getBytesAvail(State & state, SSLContextData * ssl_context);
		int getVerifyResult(State & state, SSLContextData * ssl_context);
		int getCipherSuite(State & state, SSLContextData * ssl_context);
		int getVersion(State & state, SSLContextData * ssl_context);
		int getRecordExpansion(State & state, SSLContextData * ssl_context);

		int getPeerCert(State & state, SSLContextData * ssl_context);
		int getSession(State & state, SSLContextData * ssl_context);

		static int recvCallback(void * ssl_context_data, unsigned char * data, size_t len);
		static int recvTimeoutCallback(void * ssl_context_data, unsigned char * data, size_t len, uint32_t t);
		static int sendCallback(void * ssl_context_data, const unsigned char * data, size_t len);
	};
};

#endif	
