#include "objects/BlowfishContext.hpp"

namespace luambedtls {
	mbedtls_blowfish_context * BlowfishContext::constructor(State & state, bool & managed){
		mbedtls_blowfish_context * context = new mbedtls_blowfish_context;
		mbedtls_blowfish_init(context);
		return context;
	}

	void BlowfishContext::destructor(State & state, mbedtls_blowfish_context * context){
		mbedtls_blowfish_free(context);
		delete context;
	}

	int BlowfishContext::setKey(State & state, mbedtls_blowfish_context * context){
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

			stack->push<int>(mbedtls_blowfish_setkey(context, reinterpret_cast<const unsigned char*>(key.c_str()), keyBits));
			return 1;
		}
		return 0;
	}

	int BlowfishContext::cryptECB(State & state, mbedtls_blowfish_context * context){
		Stack * stack = state.stack;
		if (stack->is<LUA_TNUMBER>(1) && stack->is<LUA_TSTRING>(2)){
			std::string input = stack->toLString(2);
			if (input.length() == MBEDTLS_BLOWFISH_BLOCKSIZE){
				unsigned char output[MBEDTLS_BLOWFISH_BLOCKSIZE];
				int mode = stack->to<int>(1);

				int result = mbedtls_blowfish_crypt_ecb(context, mode, reinterpret_cast<const unsigned char *>(input.c_str()), output);
				stack->push<int>(result);
				if (result == 0){
					stack->pushLString(std::string(reinterpret_cast<char*>(output), MBEDTLS_BLOWFISH_BLOCKSIZE));
					return 2;
				}
				else{
					return 1;
				}
			}

		}
		return 0;
	}

	int BlowfishContext::cryptCBC(State & state, mbedtls_blowfish_context * context){
		Stack * stack = state.stack;
		if (stack->is<LUA_TNUMBER>(1) && stack->is<LUA_TSTRING>(2) && stack->is<LUA_TSTRING>(3)){
			std::string ivStr = stack->toLString(2);
			std::string input = stack->toLString(3);
			size_t length = input.length();

			if (((length % MBEDTLS_BLOWFISH_BLOCKSIZE) == 0) && (ivStr.length() == MBEDTLS_BLOWFISH_BLOCKSIZE)){
				int mode = stack->to<int>(1);
				unsigned char iv[MBEDTLS_BLOWFISH_BLOCKSIZE];
				unsigned char * output = new unsigned char[length];
				memcpy(iv, ivStr.c_str(), MBEDTLS_BLOWFISH_BLOCKSIZE);

				int result = mbedtls_blowfish_crypt_cbc(context, mode, length, iv, reinterpret_cast<const unsigned char *>(input.c_str()), output);
				stack->push<int>(result);
				if (result == 0){
					stack->pushLString(std::string(reinterpret_cast<char*>(iv), MBEDTLS_BLOWFISH_BLOCKSIZE));
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

	int BlowfishContext::cryptCFB64(State & state, mbedtls_blowfish_context * context){
		Stack * stack = state.stack;
		if (stack->is<LUA_TNUMBER>(1) && stack->is<LUA_TNUMBER>(2) && stack->is<LUA_TSTRING>(3) && stack->is<LUA_TSTRING>(4)){
			std::string ivStr = stack->toLString(3);
			std::string input = stack->toLString(4);
			int length = input.length();

			if (((length % MBEDTLS_BLOWFISH_BLOCKSIZE) == 0) && (ivStr.length() == MBEDTLS_BLOWFISH_BLOCKSIZE)){
				int mode = stack->to<int>(1);
				size_t ivOff = stack->to<int>(2);;

				unsigned char iv[MBEDTLS_BLOWFISH_BLOCKSIZE];
				unsigned char * output = new unsigned char[length];
				memcpy(iv, ivStr.c_str(), MBEDTLS_BLOWFISH_BLOCKSIZE);

				int result = mbedtls_blowfish_crypt_cfb64(context, mode, length, &ivOff, iv, reinterpret_cast<const unsigned char *>(input.c_str()), output);
				stack->push<int>(result);
				if (result == 0){
					stack->push<int>(ivOff);
					stack->pushLString(std::string(reinterpret_cast<char*>(iv), MBEDTLS_BLOWFISH_BLOCKSIZE));
					stack->pushLString(std::string(reinterpret_cast<char*>(output), length));
					delete[] output;
					return 4;
				}
				else{
					delete[] output;
					return 1;
				}
			}

		}
		return 0;
	}

	int BlowfishContext::cryptCTR(State & state, mbedtls_blowfish_context * context){
		Stack * stack = state.stack;
		if (stack->is<LUA_TNUMBER>(1) && stack->is<LUA_TSTRING>(2) && stack->is<LUA_TSTRING>(3)){
			std::string nonceStr = stack->toLString(2);
			std::string input = stack->toLString(3);
			int length = input.length();

			if (((length % MBEDTLS_BLOWFISH_BLOCKSIZE) == 0) && (nonceStr.length() == MBEDTLS_BLOWFISH_BLOCKSIZE)){
				size_t ncOff = stack->to<int>(1);;

				unsigned char nonceCounter[MBEDTLS_BLOWFISH_BLOCKSIZE];
				unsigned char streamBlock[MBEDTLS_BLOWFISH_BLOCKSIZE];
				unsigned char * output = new unsigned char[length];
				memcpy(nonceCounter, nonceStr.c_str(), MBEDTLS_BLOWFISH_BLOCKSIZE);

				int result = mbedtls_blowfish_crypt_ctr(context, length, &ncOff, nonceCounter, streamBlock, reinterpret_cast<const unsigned char *>(input.c_str()), output);
				stack->push<int>(result);
				if (result == 0){
					stack->push<int>(ncOff);
					stack->pushLString(std::string(reinterpret_cast<char*>(nonceCounter), MBEDTLS_BLOWFISH_BLOCKSIZE));
					stack->pushLString(std::string(reinterpret_cast<char*>(streamBlock), MBEDTLS_BLOWFISH_BLOCKSIZE));
					stack->pushLString(std::string(reinterpret_cast<char*>(output), length));
					delete[] output;
					return 5;
				}
				else{
					delete[] output;
					return 1;
				}
			}

		}
		return 0;
	}

	void initBlowfishContext(State * state, Module & module){
		INIT_OBJECT(BlowfishContext);
	}
};
