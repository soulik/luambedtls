#include "objects/CipherInfo.hpp"

namespace luambedtls {
	mbedtls_cipher_info_t * CipherInfo::constructor(State & state, bool & managed){
		mbedtls_cipher_info_t * info = new mbedtls_cipher_info_t;
		return info;
	}

	void CipherInfo::destructor(State & state, mbedtls_cipher_info_t * info){
		delete info;
	}

	int CipherInfo::getType(State & state, mbedtls_cipher_info_t * info){
		Stack * stack = state.stack;
		stack->push<int>(info->type);
		return 1;
	}
	int CipherInfo::getMode(State & state, mbedtls_cipher_info_t * info){
		Stack * stack = state.stack;
		stack->push<int>(info->mode);
		return 1;
	}
	int CipherInfo::getBitLen(State & state, mbedtls_cipher_info_t * info){
		Stack * stack = state.stack;
		stack->push<int>(info->key_bitlen);
		return 1;
	}
	int CipherInfo::getName(State & state, mbedtls_cipher_info_t * info){
		Stack * stack = state.stack;
		stack->push<const std::string &>(info->name);
		return 1;
	}
	int CipherInfo::getIVSize(State & state, mbedtls_cipher_info_t * info){
		Stack * stack = state.stack;
		stack->push<int>(info->iv_size);
		return 1;
	}
	int CipherInfo::getFlags(State & state, mbedtls_cipher_info_t * info){
		Stack * stack = state.stack;
		stack->push<int>(info->flags);
		return 1;
	}
	int CipherInfo::getBlockSize(State & state, mbedtls_cipher_info_t * info){
		Stack * stack = state.stack;
		stack->push<int>(info->block_size);
		return 1;
	}
	int CipherInfo::getBaseCipher(State & state, mbedtls_cipher_info_t * info){
		Stack * stack = state.stack;
		stack->push<int>(info->base->cipher);
		return 1;
	}

	void initCipherInfo(State * state, Module & module){
		INIT_OBJECT(CipherInfo);
	}
};
