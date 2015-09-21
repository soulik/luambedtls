#include "objects/EntropyContext.hpp"

namespace luambedtls {
	mbedtls_entropy_context * EntropyContext::constructor(State & state, bool & managed){
		mbedtls_entropy_context * entropy_context = new mbedtls_entropy_context;
		mbedtls_entropy_init(entropy_context);
		return entropy_context;
	}

	void EntropyContext::destructor(State & state, mbedtls_entropy_context * entropy_context){
		mbedtls_entropy_free(entropy_context);
		delete entropy_context;
	}

	int EntropyContext::gather(State & state, mbedtls_entropy_context * entropy_context){
		Stack * stack = state.stack;
		stack->push<int>(mbedtls_entropy_gather(entropy_context));
		return 1;
	}

	int EntropyContext::updateManual(State & state, mbedtls_entropy_context * entropy_context){
		Stack * stack = state.stack;
		if (stack->is<LUA_TSTRING>(1)){
			const std::string buffer = stack->toLString(1);
			stack->push<int>(mbedtls_entropy_update_manual(entropy_context, reinterpret_cast<const unsigned char*>(buffer.c_str()), buffer.length()));
			return 1;
		}
		else{
			return 0;
		}
	}

	int EntropyContext::writeSeedFile(State & state, mbedtls_entropy_context * entropy_context){
		Stack * stack = state.stack;
		if (stack->is<LUA_TSTRING>(1)){
			const std::string fileName = stack->to<const std::string>(1);
			stack->push<int>(mbedtls_entropy_write_seed_file(entropy_context, fileName.c_str()));
			return 1;
		}
		else{
			return 0;
		}
	}

	int EntropyContext::updateFromSeedFile(State & state, mbedtls_entropy_context * entropy_context){
		Stack * stack = state.stack;
		if (stack->is<LUA_TSTRING>(1)){
			const std::string fileName = stack->to<const std::string>(1);
			stack->push<int>(mbedtls_entropy_update_seed_file(entropy_context, fileName.c_str()));
			return 1;
		}
		else{
			return 0;
		}
	}

	static int EntropySelfTest(State & state){
		Stack * stack = state.stack;
		stack->push<int>(mbedtls_entropy_self_test(stack->to<int>(1)));
		return 1;
	}

	void initEntropyContext(State * state, Module & module){
		INIT_OBJECT(EntropyContext);
		module["entropySelfTest"] = EntropySelfTest;
	}
};
