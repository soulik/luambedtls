#ifndef LUA_MBEDTLS_OBJECTS_CIPHERINFO_H
#define LUA_MBEDTLS_OBJECTS_CIPHERINFO_H

#include "common.hpp"

namespace luambedtls {
	class CipherInfo : public Object<mbedtls_cipher_info_t> {
	public:
		explicit CipherInfo(State * state) : Object<mbedtls_cipher_info_t>(state){
			LUTOK_PROPERTY("type", &CipherInfo::getType, &CipherInfo::nullMethod);
			LUTOK_PROPERTY("mode", &CipherInfo::getMode, &CipherInfo::nullMethod);
			LUTOK_PROPERTY("bitLen", &CipherInfo::getBitLen, &CipherInfo::nullMethod);
			LUTOK_PROPERTY("name", &CipherInfo::getName, &CipherInfo::nullMethod);
			LUTOK_PROPERTY("IVSize", &CipherInfo::getIVSize, &CipherInfo::nullMethod);
			LUTOK_PROPERTY("flags", &CipherInfo::getFlags, &CipherInfo::nullMethod);
			LUTOK_PROPERTY("blockSize", &CipherInfo::getBlockSize, &CipherInfo::nullMethod);
			LUTOK_PROPERTY("baseCipher", &CipherInfo::getBaseCipher, &CipherInfo::nullMethod);
		}

		mbedtls_cipher_info_t * constructor(State & state, bool & managed);

		void destructor(State & state, mbedtls_cipher_info_t * info);

		int getType(State & state, mbedtls_cipher_info_t * info);
		int getMode(State & state, mbedtls_cipher_info_t * info);
		int getBitLen(State & state, mbedtls_cipher_info_t * info);
		int getName(State & state, mbedtls_cipher_info_t * info);
		int getIVSize(State & state, mbedtls_cipher_info_t * info);
		int getFlags(State & state, mbedtls_cipher_info_t * info);
		int getBlockSize(State & state, mbedtls_cipher_info_t * info);
		int getBaseCipher(State & state, mbedtls_cipher_info_t * info);
	};
};

#endif	
