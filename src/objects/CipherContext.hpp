#ifndef LUA_MBEDTLS_OBJECTS_CIPHERCONTEXT_H
#define LUA_MBEDTLS_OBJECTS_CIPHERCONTEXT_H

#include "common.hpp"

namespace luambedtls {
	class CipherContext : public Object<mbedtls_cipher_context_t> {
	public:
		explicit CipherContext(State * state) : Object<mbedtls_cipher_context_t>(state){
			LUTOK_PROPERTY("blockSize", &CipherContext::getBlockSize, &CipherContext::nullMethod);
			LUTOK_PROPERTY("IVSize", &CipherContext::getIVSize, &CipherContext::nullMethod);
			LUTOK_PROPERTY("type", &CipherContext::getType, &CipherContext::nullMethod);
			LUTOK_PROPERTY("name", &CipherContext::getName, &CipherContext::nullMethod);
			LUTOK_PROPERTY("keyLen", &CipherContext::getKeyLen, &CipherContext::nullMethod);
			LUTOK_PROPERTY("operation", &CipherContext::getOperation, &CipherContext::nullMethod);
			LUTOK_PROPERTY("paddingMode", &CipherContext::nullMethod, &CipherContext::setPaddingMode);

			LUTOK_METHOD("setup", &CipherContext::setup);
			LUTOK_METHOD("setKey", &CipherContext::setKey);
			LUTOK_METHOD("setIV", &CipherContext::setIV);
			LUTOK_METHOD("reset", &CipherContext::reset);
			LUTOK_METHOD("updateAD", &CipherContext::updateAD);
			LUTOK_METHOD("update", &CipherContext::update);
			LUTOK_METHOD("finish", &CipherContext::finish);
			LUTOK_METHOD("writeTag", &CipherContext::writeTag);
			LUTOK_METHOD("checkTag", &CipherContext::checkTag);
			LUTOK_METHOD("crypt", &CipherContext::crypt);
			LUTOK_METHOD("authEncrypt", &CipherContext::authEncrypt);
			LUTOK_METHOD("authDecrypt", &CipherContext::authDecrypt);
		}

		mbedtls_cipher_context_t * constructor(State & state, bool & managed);

		void destructor(State & state, mbedtls_cipher_context_t * context);

		int setup(State & state, mbedtls_cipher_context_t * context);
		
		int getBlockSize(State & state, mbedtls_cipher_context_t * context);
		int getIVSize(State & state, mbedtls_cipher_context_t * context);
		int getType(State & state, mbedtls_cipher_context_t * context);
		int getName(State & state, mbedtls_cipher_context_t * context);
		int getKeyLen(State & state, mbedtls_cipher_context_t * context);
		int getOperation(State & state, mbedtls_cipher_context_t * context);

		int setKey(State & state, mbedtls_cipher_context_t * context);
		int setPaddingMode(State & state, mbedtls_cipher_context_t * context);
		int setIV(State & state, mbedtls_cipher_context_t * context);

		int reset(State & state, mbedtls_cipher_context_t * context);
		int updateAD(State & state, mbedtls_cipher_context_t * context);
		int update(State & state, mbedtls_cipher_context_t * context);
		int finish(State & state, mbedtls_cipher_context_t * context);
		int writeTag(State & state, mbedtls_cipher_context_t * context);
		int checkTag(State & state, mbedtls_cipher_context_t * context);
		int crypt(State & state, mbedtls_cipher_context_t * context);
		int authEncrypt(State & state, mbedtls_cipher_context_t * context);
		int authDecrypt(State & state, mbedtls_cipher_context_t * context);
	};
	void initCipherContext(State*, Module&);
	int cipherList(State &);
	int cipherInfo(State &);
};
#endif	
