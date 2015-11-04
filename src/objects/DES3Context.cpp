#include "objects/DES3Context.hpp"
#include <string.h>

namespace luambedtls {
	mbedtls_des3_context * DES3Context::constructor(State & state, bool & managed){
		mbedtls_des3_context * context = new mbedtls_des3_context;
		mbedtls_des3_init(context);
		return context;
	}

	void DES3Context::destructor(State & state, mbedtls_des3_context * context){
		mbedtls_des3_free(context);
		delete context;
	}

	int DES3Context::set2KeyEnc(State & state, mbedtls_des3_context * context){
		Stack * stack = state.stack;
		if (stack->is<LUA_TSTRING>(1)){
			const std::string key = stack->toLString(1);
			if (key.length() >= MBEDTLS_DES_KEY_SIZE * 2){
				stack->push<int>(mbedtls_des3_set2key_enc(context, reinterpret_cast<const unsigned char*>(key.c_str())));
				return 1;
			}
		}
		return 0;
	}
	int DES3Context::set2KeyDec(State & state, mbedtls_des3_context * context){
		Stack * stack = state.stack;
		if (stack->is<LUA_TSTRING>(1)){
			const std::string key = stack->toLString(1);
			if (key.length() >= MBEDTLS_DES_KEY_SIZE * 2){
				stack->push<int>(mbedtls_des3_set2key_dec(context, reinterpret_cast<const unsigned char*>(key.c_str())));
				return 1;
			}
		}
		return 0;
	}
	int DES3Context::set3KeyEnc(State & state, mbedtls_des3_context * context){
		Stack * stack = state.stack;
		if (stack->is<LUA_TSTRING>(1)){
			const std::string key = stack->toLString(1);
			if (key.length() >= MBEDTLS_DES_KEY_SIZE * 3){
				stack->push<int>(mbedtls_des3_set3key_enc(context, reinterpret_cast<const unsigned char*>(key.c_str())));
				return 1;
			}
		}
		return 0;
	}
	int DES3Context::set3KeyDec(State & state, mbedtls_des3_context * context){
		Stack * stack = state.stack;
		if (stack->is<LUA_TSTRING>(1)){
			const std::string key = stack->toLString(1);
			if (key.length() >= MBEDTLS_DES_KEY_SIZE * 3){
				stack->push<int>(mbedtls_des3_set3key_dec(context, reinterpret_cast<const unsigned char*>(key.c_str())));
				return 1;
			}
		}
		return 0;
	}
	int DES3Context::encryptECB(State & state, mbedtls_des3_context * context){
		Stack * stack = state.stack;
		if (stack->is<LUA_TSTRING>(1)){
			std::string input = stack->toLString(1);
			if (input.length() == 8){
				unsigned char output[8];
				int mode = stack->to<int>(1);

				int result = mbedtls_des3_crypt_ecb(context, reinterpret_cast<const unsigned char *>(input.c_str()), output);
				stack->push<int>(result);
				if (result == 0){
					stack->pushLString(std::string(reinterpret_cast<char*>(output), 8));
					return 2;
				}
				else{
					return 1;
				}
			}

		}
		return 0;
	}
	int DES3Context::encryptCBC(State & state, mbedtls_des3_context * context){
		Stack * stack = state.stack;
		if (stack->is<LUA_TNUMBER>(1) && stack->is<LUA_TSTRING>(2) && stack->is<LUA_TSTRING>(3)){
			std::string ivStr = stack->toLString(2);
			std::string input = stack->toLString(3);
			size_t length = input.length();

			if (((length % 8) == 0) && (ivStr.length() == 8)){
				int mode = stack->to<int>(1);
				unsigned char iv[8];
				unsigned char * output = new unsigned char[length];
				memcpy(iv, ivStr.c_str(), 16);

				int result = mbedtls_des3_crypt_cbc(context, mode, length, iv, reinterpret_cast<const unsigned char *>(input.c_str()), output);
				stack->push<int>(result);
				if (result == 0){
					stack->pushLString(std::string(reinterpret_cast<char*>(iv), 8));
					stack->pushLString(std::string(reinterpret_cast<char*>(output), length));
					delete[] output;
					return 3;
				}
				else{
					delete[] output;
					return 1;
				}
			}

		}
		return 0;
	}

	void initDES3Context(State * state, Module & module){
		INIT_OBJECT(DES3Context);
	}
};
