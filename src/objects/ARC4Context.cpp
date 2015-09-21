#include "objects/ARC4Context.hpp"

namespace luambedtls {
	mbedtls_arc4_context * ARC4Context::constructor(State & state, bool & managed){
		mbedtls_arc4_context * context = new mbedtls_arc4_context;
		mbedtls_arc4_init(context);
		return context;
	}

	void ARC4Context::destructor(State & state, mbedtls_arc4_context * context){
		mbedtls_arc4_free(context);
		delete context;
	}

	int ARC4Context::setup(State & state, mbedtls_arc4_context * context){
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

			mbedtls_arc4_setup(context, reinterpret_cast<const unsigned char*>(key.c_str()), keyBits);
		}
		return 0;
	}

	int ARC4Context::crypt(State & state, mbedtls_arc4_context * context){
		Stack * stack = state.stack;
		if (stack->is<LUA_TSTRING>(1)){
			std::string input = stack->toLString(1);
			size_t length = input.length();
			
			unsigned char * output = new unsigned char[length];

			int result = mbedtls_arc4_crypt(context, length, reinterpret_cast<const unsigned char *>(input.c_str()), output);
			stack->push<int>(result);
			if (result == 0){
				stack->pushLString(std::string(reinterpret_cast<char*>(output), length));
				delete[] output;
				return 2;
			}
			else{
				delete[] output;
				return 1;
			}
		}
		return 0;
	}

	int ARC4SelfTest(State & state){
		Stack * stack = state.stack;
		stack->push<int>(mbedtls_arc4_self_test(stack->to<int>(1)));
		return 1;
	}

	void initARC4Context(State * state, Module & module){
		INIT_OBJECT(ARC4Context);
		module["ARC4SelfTest"] = ARC4SelfTest;
	}
};
