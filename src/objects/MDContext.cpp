#include "objects/MDContext.hpp"

namespace luambedtls {
	mbedtls_md_context_t * MDContext::constructor(State & state, bool & managed){
		mbedtls_md_context_t * context = new mbedtls_md_context_t;
		mbedtls_md_init(context);
		return context;
	}

	void MDContext::destructor(State & state, mbedtls_md_context_t * context){
		mbedtls_md_free(context);
		delete context;
	}

	int md(State & state){
		Stack * stack = state.stack;
		if (stack->is<LUA_TNUMBER>(1) && stack->is<LUA_TSTRING>(2)){
			mbedtls_md_type_t mdType = static_cast<mbedtls_md_type_t>(stack->to<int>(1));
			const std::string input = stack->toLString(2);
			const size_t hashLength = 64;
			unsigned char output[hashLength];
			int result = mbedtls_md(mbedtls_md_info_from_type(mdType), reinterpret_cast<const unsigned char*>(input.c_str()), input.length(), output);
			if (result == 0){
				stack->pushLString(std::string(reinterpret_cast<char*>(output), hashLength));
			}
			else{
				stack->push<int>(result);
			}
			return 1;
		}
		return 0;
	}

	int mdFile(State & state){
		Stack * stack = state.stack;
		if (stack->is<LUA_TNUMBER>(1) && stack->is<LUA_TSTRING>(2)){
			mbedtls_md_type_t mdType = static_cast<mbedtls_md_type_t>(stack->to<int>(1));
			const std::string inputFile = stack->toLString(2);
			const size_t hashLength = 64;
			unsigned char output[hashLength];
			int result = mbedtls_md_file(mbedtls_md_info_from_type(mdType), inputFile.c_str(), output);
			if (result == 0){
				stack->pushLString(std::string(reinterpret_cast<char*>(output), hashLength));
			}
			else{
				stack->push<int>(result);
			}
			return 1;
		}
		return 0;
	}

	int mdList(State & state){
		Stack * stack = state.stack;
		const int * md_list = mbedtls_md_list();
		stack->newTable();
		for (int i = 1, mdType = *md_list; md_list != 0; i++, mdType = *md_list, md_list++){
			stack->push<int>(i);
			stack->push<int>(mdType);
			stack->setTable(-3);
		}
		return 1;
	}

	void initMDContext(State * state, Module & module){
		INIT_OBJECT(MDContext);
		module["md"] = md;
		module["mdFile"] = mdFile;
		module["mdList"] = mdList;
	}
};
