#ifndef LUA_MBEDTLS_OBJECTS_SSLCONFIG_H
#define LUA_MBEDTLS_OBJECTS_SSLCONFIG_H

#include "common.hpp"

namespace luambedtls {
	class SSLConfig : public Object<mbedtls_ssl_config> {
	public:
		explicit SSLConfig(State * state) : Object<mbedtls_ssl_config>(state){
			LUTOK_METHOD("setHandshakeTimeout", &SSLConfig::setHandshakeTimeout);
			LUTOK_METHOD("setCipherSuites", &SSLConfig::setCipherSuites);
			LUTOK_METHOD("setCAChain", &SSLConfig::setCAChain);
			LUTOK_METHOD("setOwnCert", &SSLConfig::setOwnCert);
			LUTOK_METHOD("setPSK", &SSLConfig::setPSK);
			LUTOK_METHOD("setDH", &SSLConfig::setDH);
			LUTOK_METHOD("setDHCTX", &SSLConfig::setDHCTX);
			LUTOK_METHOD("setRNG", &SSLConfig::setRNG);
			LUTOK_METHOD("setDBG", &SSLConfig::setDBG);
			LUTOK_METHOD("setCurves", &SSLConfig::setCurves);
			LUTOK_METHOD("setHashes", &SSLConfig::setHashes);
			LUTOK_METHOD("setALPNprotocols", &SSLConfig::setALPNprotocols);
			LUTOK_METHOD("minVersion", &SSLConfig::setMinVersion);
			LUTOK_METHOD("maxVersion", &SSLConfig::setMaxVersion);
			LUTOK_METHOD("renegotiationPeriod", &SSLConfig::setRenegotiationPeriod);
			LUTOK_METHOD("verify", &SSLConfig::verify);

			LUTOK_PROPERTY("endpoint", &SSLConfig::nullMethod, &SSLConfig::setupEndpoint);
			LUTOK_PROPERTY("transport", &SSLConfig::nullMethod, &SSLConfig::setupTransport);
			LUTOK_PROPERTY("authmode", &SSLConfig::nullMethod, &SSLConfig::setupAuthmode);
			LUTOK_PROPERTY("DLTSAntireplay", &SSLConfig::nullMethod, &SSLConfig::setDLTSAntireplay);
			LUTOK_PROPERTY("badMACLimit", &SSLConfig::nullMethod, &SSLConfig::setBadMACLimit);
			LUTOK_PROPERTY("profile", &SSLConfig::nullMethod, &SSLConfig::setCertProfile);
			LUTOK_PROPERTY("minBitLen", &SSLConfig::nullMethod, &SSLConfig::setMinBitLen);
			LUTOK_PROPERTY("fallback", &SSLConfig::nullMethod, &SSLConfig::setFallback);
			LUTOK_PROPERTY("encryptThenMAC", &SSLConfig::nullMethod, &SSLConfig::setEncryptThenMAC);
			LUTOK_PROPERTY("extendedMasterSecret", &SSLConfig::nullMethod, &SSLConfig::setExtendedMasterSecret);
			LUTOK_PROPERTY("arc4Support", &SSLConfig::nullMethod, &SSLConfig::setArc4Support);

			LUTOK_PROPERTY("maxFragLen", &SSLConfig::nullMethod, &SSLConfig::setMaxFragLen);
			LUTOK_PROPERTY("trucatedMAC", &SSLConfig::nullMethod, &SSLConfig::setTrucatedMAC);
			LUTOK_PROPERTY("recordSplitting", &SSLConfig::nullMethod, &SSLConfig::setRecordSplitting);
			LUTOK_PROPERTY("sessionTickets", &SSLConfig::nullMethod, &SSLConfig::setSessionTickets);
			LUTOK_PROPERTY("renegotiation", &SSLConfig::nullMethod, &SSLConfig::setRenegotiation);
			LUTOK_PROPERTY("legacyRenegotiation", &SSLConfig::nullMethod, &SSLConfig::setLegacyRenegotiation);
			LUTOK_PROPERTY("renegotiationEnforced", &SSLConfig::nullMethod, &SSLConfig::setRenegotiationEnforced);
		}

		mbedtls_ssl_config * constructor(State & state, bool & managed);

		void destructor(State & state, mbedtls_ssl_config * ssl_config);

		int setupEndpoint(State & state, mbedtls_ssl_config * ssl_config);
		int setupTransport(State & state, mbedtls_ssl_config * ssl_config);
		int setupAuthmode(State & state, mbedtls_ssl_config * ssl_config);
		int verify(State & state, mbedtls_ssl_config * ssl_config);

		int setDLTSAntireplay(State & state, mbedtls_ssl_config * ssl_config);
		int setBadMACLimit(State & state, mbedtls_ssl_config * ssl_config);
		int setHandshakeTimeout(State & state, mbedtls_ssl_config * ssl_config);

		int setCipherSuites(State & state, mbedtls_ssl_config * ssl_config);
		
		int setCertProfile(State & state, mbedtls_ssl_config * ssl_config);
		int setCAChain(State & state, mbedtls_ssl_config * ssl_config);
		int setOwnCert(State & state, mbedtls_ssl_config * ssl_config);

		int setPSK(State & state, mbedtls_ssl_config * ssl_config);
		int setDH(State & state, mbedtls_ssl_config * ssl_config);
		int setDHCTX(State & state, mbedtls_ssl_config * ssl_config);
		int setRNG(State & state, mbedtls_ssl_config * ssl_config);
		int setDBG(State & state, mbedtls_ssl_config * ssl_config);

		int setMinBitLen(State & state, mbedtls_ssl_config * ssl_config);
		int setCurves(State & state, mbedtls_ssl_config * ssl_config);
		int setHashes(State & state, mbedtls_ssl_config * ssl_config);
		int setALPNprotocols(State & state, mbedtls_ssl_config * ssl_config);

		int setMinVersion(State & state, mbedtls_ssl_config * ssl_config);
		int setMaxVersion(State & state, mbedtls_ssl_config * ssl_config);

		int setFallback(State & state, mbedtls_ssl_config * ssl_config);
		int setEncryptThenMAC(State & state, mbedtls_ssl_config * ssl_config);
		int setExtendedMasterSecret(State & state, mbedtls_ssl_config * ssl_config);
		int setArc4Support(State & state, mbedtls_ssl_config * ssl_config);

		int setMaxFragLen(State & state, mbedtls_ssl_config * ssl_config);
		int setTrucatedMAC(State & state, mbedtls_ssl_config * ssl_config);
		int setRecordSplitting(State & state, mbedtls_ssl_config * ssl_config);
		int setSessionTickets(State & state, mbedtls_ssl_config * ssl_config);
		int setRenegotiation(State & state, mbedtls_ssl_config * ssl_config);
		int setLegacyRenegotiation(State & state, mbedtls_ssl_config * ssl_config);
		int setRenegotiationEnforced(State & state, mbedtls_ssl_config * ssl_config);
		int setRenegotiationPeriod(State & state, mbedtls_ssl_config * ssl_config);

		static void debugCallback(void * context, int level, const char * file, int line, const char * str);
	};
};

#endif	
