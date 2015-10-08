#include "objects/MDinfo.hpp"

namespace luambedtls {
	mbedtls_md_info_t * MDinfo::constructor(State & state, bool & managed){
		mbedtls_md_info_t * object = new mbedtls_md_info_t;
		return object;
	}

	void MDinfo::destructor(State & state, mbedtls_md_info_t * object){
		delete object;
	}

	int MDinfo::getBlockSize(State & state, mbedtls_md_info_t * object){
		Stack * stack = state.stack;
		stack->push<int>(object->block_size);
		return 1;
	}
	int MDinfo::getSize(State & state, mbedtls_md_info_t * object){
		Stack * stack = state.stack;
		stack->push<int>(mbedtls_md_get_size(object));
		return 1;
	}
	int MDinfo::getType(State & state, mbedtls_md_info_t * object){
		Stack * stack = state.stack;
		stack->push<int>(static_cast<int>(mbedtls_md_get_type(object)));
		return 1;
	}
	int MDinfo::getName(State & state, mbedtls_md_info_t * object){
		Stack * stack = state.stack;
		const char * name = mbedtls_md_get_name(object);
		if (name){
			stack->push<const std::string &>(name);
			return 1;
		}
		return 0;
	}

	int MDinfo::md(State & state, mbedtls_md_info_t * object){
		Stack * stack = state.stack;
		if (stack->is<LUA_TSTRING>(1)){
			const std::string input = stack->toLString(1);
			const size_t hashLength = 64;
			unsigned char output[hashLength];
			int result = mbedtls_md(object, reinterpret_cast<const unsigned char *>(input.c_str()), input.length(), output);
			if (result == 0){
				stack->pushLString(std::string(reinterpret_cast<char *>(output), hashLength));
			}
			else{
				stack->push<int>(result);
			}
			return 1;
		}
		return 0;
	}
	int MDinfo::mdHMAC(State & state, mbedtls_md_info_t * object){
		Stack * stack = state.stack;
		if (stack->is<LUA_TSTRING>(1) && stack->is<LUA_TSTRING>(2)){
			const std::string key = stack->toLString(1);
			const std::string input = stack->toLString(2);
			const size_t hashLength = 64;
			unsigned char output[hashLength];
			int result = mbedtls_md_hmac(object,
				reinterpret_cast<const unsigned char *>(key.c_str()), key.length(),
				reinterpret_cast<const unsigned char *>(input.c_str()), input.length(), output);
			if (result == 0){
				stack->pushLString(std::string(reinterpret_cast<char *>(output), hashLength));
			}
			else{
				stack->push<int>(result);
			}
			return 1;
		}
		return 0;
	}

	void initMDinfo(State * state, Module & module){
		INIT_OBJECT(MDinfo);
	}
};
