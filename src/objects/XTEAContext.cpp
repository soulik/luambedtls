#include "objects/XTEAContext.hpp"

namespace luambedtls {
	mbedtls_xtea_context * XTEAContext::constructor(State & state, bool & managed){
		mbedtls_xtea_context * context = new mbedtls_xtea_context;
		mbedtls_xtea_init(context);
		return context;
	}

	void XTEAContext::destructor(State & state, mbedtls_xtea_context * context){
		mbedtls_xtea_free(context);
		delete context;
	}

	int XTEAContext::setup(State & state, mbedtls_xtea_context * context){
		Stack * stack = state.stack;
		if (stack->is<LUA_TSTRING>(1)){
			const std::string key = stack->toLString(1);
			if (key.length() == 16){
				mbedtls_xtea_setup(context, reinterpret_cast<const unsigned char*>(key.c_str()));
			}
		}
		return 0;
	}
	int XTEAContext::cryptECB(State & state, mbedtls_xtea_context * context){
		Stack * stack = state.stack;
		if (stack->is<LUA_TNUMBER>(1) && stack->is<LUA_TSTRING>(2)){
			std::string input = stack->toLString(2);
			if (input.length() == 8){
				unsigned char output[8];
				int mode = stack->to<int>(1);

				int result = mbedtls_xtea_crypt_ecb(context, mode, reinterpret_cast<const unsigned char *>(input.c_str()), output);
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
	int XTEAContext::cryptCBC(State & state, mbedtls_xtea_context * context){
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

				int result = mbedtls_xtea_crypt_cbc(context, mode, length, iv, reinterpret_cast<const unsigned char *>(input.c_str()), output);
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

	int XTEASelfTest(State & state){
		Stack * stack = state.stack;
		stack->push<int>(mbedtls_xtea_self_test(stack->to<int>(1)));
		return 1;
	}

	void initXTEAContext(State * state, Module & module){
		INIT_OBJECT(XTEAContext);
		module["XTEASelfTest"] = XTEASelfTest;
	}
};
