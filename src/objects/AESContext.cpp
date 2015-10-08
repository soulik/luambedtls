#include "objects/AESContext.hpp"

namespace luambedtls {
	mbedtls_aes_context * AESContext::constructor(State & state, bool & managed){
		mbedtls_aes_context * context = new mbedtls_aes_context;
		mbedtls_aes_init(context);
		return context;
	}

	void AESContext::destructor(State & state, mbedtls_aes_context * context){
		mbedtls_aes_free(context);
		delete context;
	}

	int AESContext::setKeyEnc(State & state, mbedtls_aes_context * context){
		Stack * stack = state.stack;
		if (stack->is<LUA_TSTRING>(1)){
			const std::string key = stack->toLString(1);
			unsigned int realBits = key.length() * 8;
			unsigned int keyBits;

			if (stack->is<LUA_TNUMBER>(2)){
				keyBits = stack->to<int>(2);
				if (keyBits > realBits){
					keyBits = realBits;
				}
			}
			else{
				keyBits = realBits;
			}


			stack->push<int>(mbedtls_aes_setkey_enc(context, reinterpret_cast<const unsigned char*>(key.c_str()), keyBits));
			return 1;
		}
		return 0;
	}
	int AESContext::setKeyDec(State & state, mbedtls_aes_context * context){
		Stack * stack = state.stack;
		if (stack->is<LUA_TSTRING>(1)){
			const std::string key = stack->toLString(1);
			unsigned int realBits = key.length() * 8;
			unsigned int keyBits;

			if (stack->is<LUA_TNUMBER>(2)){
				keyBits = stack->to<int>(2);
				if (keyBits > realBits){
					keyBits = realBits;
				}
			}
			else{
				keyBits = realBits;
			}


			stack->push<int>(mbedtls_aes_setkey_dec(context, reinterpret_cast<const unsigned char*>(key.c_str()), keyBits));
			return 1;
		}
		return 0;
	}
	int AESContext::cryptECB(State & state, mbedtls_aes_context * context){
		Stack * stack = state.stack;
		if (stack->is<LUA_TNUMBER>(1) && stack->is<LUA_TSTRING>(2)){
			std::string input = stack->toLString(2);
			if (input.length() == 16){
				unsigned char output[16];
				int mode = stack->to<int>(1);

				int result = mbedtls_aes_crypt_ecb(context, mode, reinterpret_cast<const unsigned char *>(input.c_str()), output);
				if (result == 0){
					stack->pushLString(std::string(reinterpret_cast<char*>(output), 16));
				}
				else{
					stack->push<int>(result);
				}
				return 1;
			}

		}
		return 0;
	}
	int AESContext::cryptCBC(State & state, mbedtls_aes_context * context){
		Stack * stack = state.stack;
		if (stack->is<LUA_TNUMBER>(1) && stack->is<LUA_TSTRING>(2) && stack->is<LUA_TSTRING>(3)){
			std::string ivStr = stack->toLString(2);
			std::string input = stack->toLString(3);
			size_t length = input.length();
			
			if (((length % 16) == 0) && (ivStr.length() == 16)){
				int mode = stack->to<int>(1);
				unsigned char iv[16];
				unsigned char * output = new unsigned char[length];
				memcpy(iv, ivStr.c_str(), 16);

				int result = mbedtls_aes_crypt_cbc(context, mode, length, iv, reinterpret_cast<const unsigned char *>(input.c_str()), output);
				if (result == 0){
					stack->pushLString(std::string(reinterpret_cast<char*>(iv), 16));
					stack->pushLString(std::string(reinterpret_cast<char*>(output), length));
					delete[] output;
					return 2;
				}
				else{
					stack->push<int>(result);
					delete[] output;
					return 1;
				}
			}
			else{
				stack->push<bool>(false);
				return 1;
			}

		}
		return 0;
	}
	int AESContext::cryptCFB128(State & state, mbedtls_aes_context * context){
		Stack * stack = state.stack;
		if (stack->is<LUA_TNUMBER>(1) && stack->is<LUA_TNUMBER>(2) && stack->is<LUA_TSTRING>(3) && stack->is<LUA_TSTRING>(4)){
			std::string ivStr = stack->toLString(3);
			std::string input = stack->toLString(4);
			int length = input.length();

			if (((length % 16) == 0) && (ivStr.length() == 16)){
				int mode = stack->to<int>(1);
				size_t ivOff = stack->to<int>(2);

				unsigned char iv[16];
				unsigned char * output = new unsigned char[length];
				memcpy(iv, ivStr.c_str(), 16);

				int result = mbedtls_aes_crypt_cfb128(context, mode, length, &ivOff, iv, reinterpret_cast<const unsigned char *>(input.c_str()), output);
				if (result == 0){
					stack->push<int>(ivOff);
					stack->pushLString(std::string(reinterpret_cast<char*>(iv), 16));
					stack->pushLString(std::string(reinterpret_cast<char*>(output), length));
					delete[] output;
					return 3;
				}
				else{
					stack->push<int>(result);
					delete[] output;
					return 1;
				}
			}
			else{
				stack->push<bool>(false);
				return 1;
			}
		}
		return 0;
	}
	int AESContext::cryptCFB8(State & state, mbedtls_aes_context * context){
		Stack * stack = state.stack;
		if (stack->is<LUA_TNUMBER>(1) && stack->is<LUA_TSTRING>(2) && stack->is<LUA_TSTRING>(3)){
			std::string ivStr = stack->toLString(2);
			std::string input = stack->toLString(3);
			size_t length = input.length();

			if (((length % 16) == 0) && (ivStr.length() == 16)){
				int mode = stack->to<int>(1);
				unsigned char iv[16];
				unsigned char * output = new unsigned char[length];
				memcpy(iv, ivStr.c_str(), 16);

				int result = mbedtls_aes_crypt_cfb8(context, mode, length, iv, reinterpret_cast<const unsigned char *>(input.c_str()), output);
				if (result == 0){
					stack->pushLString(std::string(reinterpret_cast<char*>(iv), 16));
					stack->pushLString(std::string(reinterpret_cast<char*>(output), length));
					delete[] output;
					return 2;
				}
				else{
					stack->push<int>(result);
					delete[] output;
					return 1;
				}
			}
			else{
				stack->push<bool>(false);
				return 1;
			}
		}
		return 0;
	}
	int AESContext::cryptCTR(State & state, mbedtls_aes_context * context){
		Stack * stack = state.stack;
		if (stack->is<LUA_TNUMBER>(1) && stack->is<LUA_TSTRING>(2) && stack->is<LUA_TSTRING>(3)){
			std::string nonceStr = stack->toLString(2);
			std::string input = stack->toLString(3);
			int length = input.length();

			if (((length % 16) == 0) && (nonceStr.length() == 16)){
				size_t ncOff = stack->to<int>(1);;

				unsigned char nonceCounter[16];
				unsigned char streamBlock[16];
				unsigned char * output = new unsigned char[length];
				memcpy(nonceCounter, nonceStr.c_str(), 16);

				int result = mbedtls_aes_crypt_ctr(context, length, &ncOff, nonceCounter, streamBlock, reinterpret_cast<const unsigned char *>(input.c_str()), output);
				if (result == 0){
					stack->push<int>(ncOff);
					stack->pushLString(std::string(reinterpret_cast<char*>(nonceCounter), 16));
					stack->pushLString(std::string(reinterpret_cast<char*>(streamBlock), 16));
					stack->pushLString(std::string(reinterpret_cast<char*>(output), length));
					delete[] output;
					return 4;
				}
				else{
					stack->push<int>(result);
					delete[] output;
					return 1;
				}
			}
			else{
				stack->push<bool>(false);
				return 1;
			}
		}
		return 0;
	}
	int AESContext::encrypt(State & state, mbedtls_aes_context * context){
		Stack * stack = state.stack;
		if (stack->is<LUA_TSTRING>(1)){
			std::string input = stack->toLString(1);
			if (input.length() == 16){
				unsigned char output[16];

				mbedtls_aes_encrypt(context, reinterpret_cast<const unsigned char *>(input.c_str()), output);
				stack->pushLString(std::string(reinterpret_cast<char*>(output), 16));
				return 1;
			}
			else{
				stack->push<bool>(false);
				return 1;
			}
		}
		return 0;
	}
	int AESContext::decrypt(State & state, mbedtls_aes_context * context){
		Stack * stack = state.stack;
		if (stack->is<LUA_TSTRING>(1)){
			std::string input = stack->toLString(1);
			if (input.length() == 16){
				unsigned char output[16];

				mbedtls_aes_decrypt(context, reinterpret_cast<const unsigned char *>(input.c_str()), output);
				stack->pushLString(std::string(reinterpret_cast<char*>(output), 16));
				return 1;
			}
			else{
				stack->push<bool>(false);
				return 1;
			}
		}
		return 0;
	}

	int AESSelfTest(State & state){
		Stack * stack = state.stack;
		stack->push<int>(mbedtls_aes_self_test(stack->to<int>(1)));
		return 1;
	}

	void initAESContext(State * state, Module & module){
		INIT_OBJECT(AESContext);
		module["AESSelfTest"] = AESSelfTest;
	}
};
