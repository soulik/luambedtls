#include "objects/DESContext.hpp"
#include <string.h>

namespace luambedtls {
	mbedtls_des_context * DESContext::constructor(State & state, bool & managed){
		mbedtls_des_context * context = new mbedtls_des_context;
		mbedtls_des_init(context);
		return context;
	}

	void DESContext::destructor(State & state, mbedtls_des_context * context){
		mbedtls_des_free(context);
		delete context;
	}
	int DESContext::setKeyEnc(State & state, mbedtls_des_context * context){
		Stack * stack = state.stack;
		if (stack->is<LUA_TSTRING>(1)){
			const std::string key = stack->toLString(1);
			if (key.length() >= MBEDTLS_DES_KEY_SIZE){
				stack->push<int>(mbedtls_des_setkey_enc(context, reinterpret_cast<const unsigned char*>(key.c_str())));
				return 1;
			}
		}
		return 0;
	}
	int DESContext::setKeyDec(State & state, mbedtls_des_context * context){
		Stack * stack = state.stack;
		if (stack->is<LUA_TSTRING>(1)){
			const std::string key = stack->toLString(1);
			if (key.length() >= MBEDTLS_DES_KEY_SIZE){
				stack->push<int>(mbedtls_des_setkey_dec(context, reinterpret_cast<const unsigned char*>(key.c_str())));
				return 1;
			}
		}
		return 0;
	}
	int DESContext::encryptECB(State & state, mbedtls_des_context * context){
		Stack * stack = state.stack;
		if (stack->is<LUA_TSTRING>(1)){
			std::string input = stack->toLString(1);
			if (input.length() == 8){
				unsigned char output[8];
				int mode = stack->to<int>(1);

				int result = mbedtls_des_crypt_ecb(context, reinterpret_cast<const unsigned char *>(input.c_str()), output);
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
	int DESContext::encryptCBC(State & state, mbedtls_des_context * context){
		Stack * stack = state.stack;
		if (stack->is<LUA_TNUMBER>(1) && stack->is<LUA_TSTRING>(2) && stack->is<LUA_TSTRING>(3)){
			std::string ivStr = stack->toLString(2);
			std::string input = stack->toLString(3);
			size_t length = input.length();

			if (((length % 8) == 0) && (ivStr.length() == 8)){
				int mode = stack->to<int>(1);
				unsigned char iv[8];
				unsigned char * output = new unsigned char[length];
				memcpy(iv, ivStr.c_str(), 8);

				int result = mbedtls_des_crypt_cbc(context, mode, length, iv, reinterpret_cast<const unsigned char *>(input.c_str()), output);
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

	int DESSetKey(State & state){
		Stack * stack = state.stack;
		uint32_t SK[32];

		if (stack->is<LUA_TSTRING>(1)){
			memset(SK, 0, sizeof(SK));

			if (stack->is<LUA_TTABLE>(2)){
				size_t SKitems = stack->objLen(2);
				if (SKitems == 32){
					for (int i = 0; i < 32; i++){
						stack->getField(i + 1, 2);
						SK[i] = static_cast<uint32_t>(stack->to<int>(-1));
						stack->pop(1);
					}
				}
			}

			std::string key = stack->toLString(1);
			if (key.length() >= MBEDTLS_DES_KEY_SIZE){
				mbedtls_des_setkey(SK, reinterpret_cast<const unsigned char *>(key.c_str()));
				
				stack->newTable();
				for (int i = 0; i < 32; i++){
					stack->push<int>(i + 1);
					stack->push<int>(SK[i]);
					stack->setTable();
				}
				return 1;
			}
		}
		return 0;
	}

	int DESSetKeyParity(State & state){
		Stack * stack = state.stack;
		if (stack->is<LUA_TSTRING>(1)){
			std::string keyStr = stack->toLString(1);
			if (keyStr.length() >= MBEDTLS_DES_KEY_SIZE){
				unsigned char key[MBEDTLS_DES_KEY_SIZE];
				memcpy(key, keyStr.c_str(), MBEDTLS_DES_KEY_SIZE);
				mbedtls_des_key_set_parity(key);
				stack->pushLString(std::string(reinterpret_cast<char *>(key), MBEDTLS_DES_KEY_SIZE));
				return 1;
			}
		}
		return 0;
	}
	int DESCheckKeyParity(State & state){
		Stack * stack = state.stack;
		if (stack->is<LUA_TSTRING>(1)){
			std::string key = stack->toLString(1);
			if (key.length() >= MBEDTLS_DES_KEY_SIZE){
				stack->push<int>(mbedtls_des_key_check_key_parity(reinterpret_cast<const unsigned char *>(key.c_str())));
				return 1;
			}
		}
		return 0;
	}
	int DESKeyCheckWeak(State & state){
		Stack * stack = state.stack;
		if (stack->is<LUA_TSTRING>(1)){
			std::string key = stack->toLString(1);
			if (key.length() >= MBEDTLS_DES_KEY_SIZE){
				stack->push<int>(mbedtls_des_key_check_weak(reinterpret_cast<const unsigned char *>(key.c_str())));
				return 1;
			}
		}
		return 0;
	}

	int DESSelfTest(State & state){
		Stack * stack = state.stack;
		stack->push<int>(mbedtls_des_self_test(stack->to<int>(1)));
		return 1;
	}

	void initDESContext(State * state, Module & module){
		INIT_OBJECT(DESContext);
		module["DESSetKey"] = DESSetKey;
		module["DESSetKeyParity"] = DESSetKeyParity;
		module["DESCheckKeyParity"] = DESCheckKeyParity;
		module["DESKeyCheckWeak"] = DESKeyCheckWeak;
		module["DESSelfTest"] = DESSelfTest;
	}
};
