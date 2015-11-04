#include "objects/GCMContext.hpp"
#include <string.h>

namespace luambedtls {
	mbedtls_gcm_context * GCMContext::constructor(State & state, bool & managed){
		mbedtls_gcm_context * context = new mbedtls_gcm_context;
		mbedtls_gcm_init(context);
		return context;
	}

	void GCMContext::destructor(State & state, mbedtls_gcm_context * context){
		mbedtls_gcm_free(context);
		delete context;
	}

	int GCMContext::setKey(State & state, mbedtls_gcm_context * context){
		Stack * stack = state.stack;
		if (stack->is<LUA_TNUMBER>(1) && stack->is<LUA_TSTRING>(2)){
			mbedtls_cipher_id_t cipher = static_cast<mbedtls_cipher_id_t>(stack->to<int>(1));

			const std::string key = stack->toLString(2);
			unsigned int realBits = key.length() * 8;
			unsigned int keyBits;

			if (stack->is<LUA_TNUMBER>(3)){
				keyBits = stack->to<int>(3);
				if (keyBits > realBits){
					keyBits = realBits;
				}
			}
			else{
				keyBits = realBits;
			}

			if ((keyBits == 128) || (keyBits == 192) || (keyBits == 256)){
				stack->push<int>(mbedtls_gcm_setkey(context, cipher, reinterpret_cast<const unsigned char*>(key.c_str()), keyBits));
				return 1;
			}
		}
		return 0;
	}
	int GCMContext::cryptAndTag(State & state, mbedtls_gcm_context * context){
		Stack * stack = state.stack;
		if (stack->is<LUA_TNUMBER>(1) && stack->is<LUA_TSTRING>(2) && stack->is<LUA_TSTRING>(3) && stack->is<LUA_TNUMBER>(4)){
			std::string ivStr = stack->toLString(2);
			std::string input = stack->toLString(3);

			size_t ivLength = ivStr.length();
			size_t length = input.length();

			unsigned char * additionalData = nullptr;
			size_t addLength = 0;

			size_t tagLength = stack->to<int>(4);

			if ((tagLength >= 4) && (tagLength <= 16)){

				if (stack->is<LUA_TSTRING>(5)){
					std::string additional = stack->toLString(5);
					addLength = additional.length();
					additionalData = new unsigned char[addLength];
					memcpy(additionalData, additional.c_str(), addLength);
				}

				int mode = stack->to<int>(1);
				unsigned char * tag = new unsigned char[tagLength];
				unsigned char * output = new unsigned char[length];

				int result = mbedtls_gcm_crypt_and_tag(context, mode, length,
					reinterpret_cast<const unsigned char*>(ivStr.c_str()), ivLength,
					additionalData, addLength,
					reinterpret_cast<const unsigned char *>(input.c_str()),
					output,
					tagLength, tag);

				if (additionalData){
					delete[] additionalData;
				}

				
				if (result == 0){
					stack->pushLString(std::string(reinterpret_cast<char*>(output), length));
					stack->pushLString(std::string(reinterpret_cast<char*>(tag), tagLength));
					delete[] output;
					delete[] tag;
					return 2;
				}
				else{
					delete[] output;
					delete[] tag;
					stack->push<int>(result);
					return 1;
				}
			}
		}
		return 0;
	}
	int GCMContext::authDecrypt(State & state, mbedtls_gcm_context * context){
		Stack * stack = state.stack;
		if (stack->is<LUA_TSTRING>(1) && stack->is<LUA_TSTRING>(2) && stack->is<LUA_TSTRING>(3)){
			std::string ivStr = stack->toLString(1);
			std::string input = stack->toLString(2);
			std::string tagStr = stack->toLString(3);

			size_t ivLength = ivStr.length();
			size_t length = input.length();
			size_t tagLength = tagStr.length();

			unsigned char * additionalData = nullptr;
			size_t addLength = 0;

			if ((tagLength >= 4) && (tagLength <= 16)){

				if (stack->is<LUA_TSTRING>(4)){
					std::string additional = stack->toLString(4);
					addLength = additional.length();
					additionalData = new unsigned char[addLength];
					memcpy(additionalData, additional.c_str(), addLength);
				}

				unsigned char * output = new unsigned char[length + 8];

				int result = mbedtls_gcm_auth_decrypt(context, length,
					reinterpret_cast<const unsigned char*>(ivStr.c_str()), ivLength,
					additionalData, addLength,
					reinterpret_cast<const unsigned char *>(tagStr.c_str()), tagLength,
					reinterpret_cast<const unsigned char *>(input.c_str()),	output
					);

				if (additionalData){
					delete[] additionalData;
				}
	
				if (result == 0){
					stack->pushLString(std::string(reinterpret_cast<char*>(output), length));
					delete[] output;
				}
				else{
					delete[] output;
					stack->push<int>(result);
				}
				return 1;
			}
		}
		return 0;
	}
	int GCMContext::starts(State & state, mbedtls_gcm_context * context){
		Stack * stack = state.stack;
		if (stack->is<LUA_TNUMBER>(1) && stack->is<LUA_TSTRING>(2)){
			std::string ivStr = stack->toLString(2);

			size_t ivLength = ivStr.length();

			unsigned char * additionalData = nullptr;
			size_t addLength = 0;

			if (stack->is<LUA_TSTRING>(3)){
				std::string additional = stack->toLString(3);
				addLength = additional.length();
				additionalData = new unsigned char[addLength];
				memcpy(additionalData, additional.c_str(), addLength);
			}

			int mode = stack->to<int>(1);

			int result = mbedtls_gcm_starts(context, mode,
				reinterpret_cast<const unsigned char*>(ivStr.c_str()), ivLength,
				additionalData, addLength);

			if (additionalData){
				delete[] additionalData;
			}

			stack->push<int>(result);
			return 1;
		}
		return 0;
	}
	int GCMContext::update(State & state, mbedtls_gcm_context * context){
		Stack * stack = state.stack;
		if (stack->is<LUA_TSTRING>(1)){
			std::string input = stack->toLString(1);
			size_t length = input.length();

			unsigned char * output = new unsigned char[length];

			int result = mbedtls_gcm_update(context, length, reinterpret_cast<const unsigned char *>(input.c_str()), output);

			
			if (result == 0){
				stack->pushLString(std::string(reinterpret_cast<char*>(output), length));
				delete[] output;
			}
			else{
				delete[] output;
				stack->push<int>(result);
			}
			return 1;
		}
		return 0;
	}
	int GCMContext::finish(State & state, mbedtls_gcm_context * context){
		Stack * stack = state.stack;
		if (stack->is<LUA_TNUMBER>(1)){
			size_t tagLength = stack->to<int>(1);

			if ((tagLength >= 4) && (tagLength <= 16)){
				unsigned char * tag = new unsigned char[tagLength];

				int result = mbedtls_gcm_finish(context, tag, tagLength);

				
				if (result == 0){
					stack->pushLString(std::string(reinterpret_cast<char*>(tag), tagLength));
					delete[] tag;
				}
				else{
					delete[] tag;
					stack->push<int>(result);
				}
				return 1;
			}
		}
		return 0;
	}

	int GCMSelfTest(State & state){
		Stack * stack = state.stack;
		stack->push<int>(mbedtls_gcm_self_test(stack->to<int>(1)));
		return 1;
	}

	void initGCMContext(State * state, Module & module){
		INIT_OBJECT(GCMContext);
		module["GCMSelfTest"] = GCMSelfTest;
	}
};
