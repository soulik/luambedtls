#ifndef LUA_MBEDTLS_OBJECTS_PKCONTEXT_H
#define LUA_MBEDTLS_OBJECTS_PKCONTEXT_H

#include "common.hpp"

namespace luambedtls {
	class PKContext : public Object<mbedtls_pk_context> {
	public:
		explicit PKContext(State * state) : Object<mbedtls_pk_context>(state){
			LUTOK_PROPERTY("rsa", &PKContext::getRSA, &PKContext::nullMethod);
			LUTOK_PROPERTY("ec", &PKContext::getEC, &PKContext::nullMethod);
			LUTOK_PROPERTY("type", &PKContext::getType, &PKContext::nullMethod);
			LUTOK_PROPERTY("name", &PKContext::getName, &PKContext::nullMethod);
			LUTOK_PROPERTY("bitLen", &PKContext::getBitLen, &PKContext::nullMethod);
			LUTOK_PROPERTY("length", &PKContext::getLength, &PKContext::nullMethod);

			LUTOK_METHOD("setup", &PKContext::setup);
			LUTOK_METHOD("canDo", &PKContext::canDo);
			LUTOK_METHOD("verify", &PKContext::verify);
			LUTOK_METHOD("verifyExt", &PKContext::verifyExt);
			LUTOK_METHOD("sign", &PKContext::sign);
			LUTOK_METHOD("decrypt", &PKContext::decrypt);
			LUTOK_METHOD("encrypt", &PKContext::encrypt);
			LUTOK_METHOD("checkPair", &PKContext::checkPair);
			LUTOK_METHOD("parseKey", &PKContext::parseKey);
			LUTOK_METHOD("parsePublicKey", &PKContext::parsePublicKey);
			LUTOK_METHOD("parseKeyFile", &PKContext::parseKeyFile);
			LUTOK_METHOD("parsePublicKeyFile", &PKContext::parsePublicKeyFile);
			LUTOK_METHOD("writeKeyDER", &PKContext::writeKeyDER);
			LUTOK_METHOD("writePublicKeyDER", &PKContext::writePublicKeyDER);
			LUTOK_METHOD("writeKeyPEM", &PKContext::writeKeyPEM);
			LUTOK_METHOD("writePublicKeyPEM", &PKContext::writePublicKeyPEM);
		}

		mbedtls_pk_context * constructor(State & state, bool & managed);

		void destructor(State & state, mbedtls_pk_context * context);
		
		int getRSA(State & state, mbedtls_pk_context * context);
		int getEC(State & state, mbedtls_pk_context * context);
		int getType(State & state, mbedtls_pk_context * context);
		int getName(State & state, mbedtls_pk_context * context);
		int getBitLen(State & state, mbedtls_pk_context * context);
		int getLength(State & state, mbedtls_pk_context * context);

		int setup(State & state, mbedtls_pk_context * context);
		int canDo(State & state, mbedtls_pk_context * context);
		int verify(State & state, mbedtls_pk_context * context);
		int verifyExt(State & state, mbedtls_pk_context * context);
		int sign(State & state, mbedtls_pk_context * context);
		int decrypt(State & state, mbedtls_pk_context * context);
		int encrypt(State & state, mbedtls_pk_context * context);
		int checkPair(State & state, mbedtls_pk_context * context);
		int parseKey(State & state, mbedtls_pk_context * context);
		int parsePublicKey(State & state, mbedtls_pk_context * context);
		int parseKeyFile(State & state, mbedtls_pk_context * context);
		int parsePublicKeyFile(State & state, mbedtls_pk_context * context);
		int writeKeyDER(State & state, mbedtls_pk_context * context);
		int writePublicKeyDER(State & state, mbedtls_pk_context * context);
		int writeKeyPEM(State & state, mbedtls_pk_context * context);
		int writePublicKeyPEM(State & state, mbedtls_pk_context * context);
		int parseSubPublicKey(State & state, mbedtls_pk_context * context);
		int writePublicKey(State & state, mbedtls_pk_context * context);
		int loadFile(State & state, mbedtls_pk_context * context);
	};
	void initPKContext(State*, Module&);
};
#endif	
