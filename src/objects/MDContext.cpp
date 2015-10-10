#include "objects/MDContext.hpp"
#include "objects/MDinfo.hpp"

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

	int MDContext::clone(State & state, mbedtls_md_context_t * context){
		Stack * stack = state.stack;
		MDContext * interfaceMD = OBJECT_IFACE(MDContext);
		mbedtls_md_context_t * dest = interfaceMD->get(1);
		if (dest){
			stack->push<int>(mbedtls_md_clone(dest, context));
			return 1;
		}
		return 0;
	}
	int MDContext::setup(State & state, mbedtls_md_context_t * context){
		Stack * stack = state.stack;
		MDinfo * interfaceMDinfo = OBJECT_IFACE(MDinfo);
		mbedtls_md_info_t * info = interfaceMDinfo->get(1);
		if (info){
			int hmac = 0;
			if (stack->is<LUA_TNUMBER>(2)){
				hmac = stack->to<int>(2);
			}
			stack->push<int>(mbedtls_md_setup(context, info, hmac));
			return 1;
		}
		return 0;
	}

	int MDContext::starts(State & state, mbedtls_md_context_t * context){
		Stack * stack = state.stack;
		stack->push<int>(mbedtls_md_starts(context));
		return 1;
	}
	int MDContext::update(State & state, mbedtls_md_context_t * context){
		Stack * stack = state.stack;
		if (stack->is<LUA_TSTRING>(1)){
			const std::string input = stack->toLString(1);
			stack->push<int>(mbedtls_md_update(context, reinterpret_cast<const unsigned char *>(input.c_str()), input.length()));
			return 1;
		}
		return 0;
	}
	int MDContext::finish(State & state, mbedtls_md_context_t * context){
		Stack * stack = state.stack;
		const size_t hashLength = context->md_info->size;
		unsigned char * output = new unsigned char[hashLength];
		int result = mbedtls_md_finish(context, output);
		if (result == 0){
			stack->pushLString(std::string(reinterpret_cast<char *>(output), hashLength));
		}
		else{
			stack->push<int>(result);
		}
		delete[] output;
		return 1;
	}

	int MDContext::HMACstarts(State & state, mbedtls_md_context_t * context){
		Stack * stack = state.stack;
		if (stack->is<LUA_TSTRING>(1)){
			const std::string key = stack->toLString(1);
			stack->push<int>(mbedtls_md_hmac_starts(context, reinterpret_cast<const unsigned char *>(key.c_str()), key.length()));
			return 1;
		}
		else{
			return 0;
		}
	}
	int MDContext::HMACupdate(State & state, mbedtls_md_context_t * context){
		Stack * stack = state.stack;
		if (stack->is<LUA_TSTRING>(1)){
			const std::string input = stack->toLString(1);
			stack->push<int>(mbedtls_md_hmac_update(context, reinterpret_cast<const unsigned char *>(input.c_str()), input.length()));
			return 1;
		}
		return 0;
	}
	int MDContext::HMACfinish(State & state, mbedtls_md_context_t * context){
		Stack * stack = state.stack;
		const size_t hashLength = context->md_info->size;
		unsigned char * output = new unsigned char[hashLength];
		int result = mbedtls_md_hmac_finish(context, output);
		if (result == 0){
			stack->pushLString(std::string(reinterpret_cast<char *>(output), hashLength));
		}
		else{
			stack->push<int>(result);
		}
		delete[] output;
		return 1;
	}
	int MDContext::HMACreset(State & state, mbedtls_md_context_t * context){
		Stack * stack = state.stack;
		stack->push<int>(mbedtls_md_hmac_reset(context));
		return 1;
	}

	int md(State & state){
		Stack * stack = state.stack;
		if (stack->is<LUA_TNUMBER>(1) && stack->is<LUA_TSTRING>(2)){
			mbedtls_md_type_t mdType = static_cast<mbedtls_md_type_t>(stack->to<int>(1));
			const std::string input = stack->toLString(2);

			const mbedtls_md_info_t * info = mbedtls_md_info_from_type(mdType);
			const size_t hashLength = info->size;
			unsigned char * output = new unsigned char[hashLength];

			int result = mbedtls_md(info, reinterpret_cast<const unsigned char*>(input.c_str()), input.length(), output);
			if (result == 0){
				stack->pushLString(std::string(reinterpret_cast<char*>(output), hashLength));
			}
			else{
				stack->push<int>(result);
			}
			delete[] output;
			return 1;
		}
		return 0;
	}

	int mdFile(State & state){
		Stack * stack = state.stack;
		if (stack->is<LUA_TNUMBER>(1) && stack->is<LUA_TSTRING>(2)){
			mbedtls_md_type_t mdType = static_cast<mbedtls_md_type_t>(stack->to<int>(1));
			const std::string inputFile = stack->toLString(2);

			const mbedtls_md_info_t * info = mbedtls_md_info_from_type(mdType);
			const size_t hashLength = info->size;
			unsigned char * output = new unsigned char[hashLength];
			int result = mbedtls_md_file(info, inputFile.c_str(), output);
			if (result == 0){
				stack->pushLString(std::string(reinterpret_cast<char*>(output), hashLength));
			}
			else{
				stack->push<int>(result);
			}
			delete[] output;
			return 1;
		}
		return 0;
	}

	int mdList(State & state){
		Stack * stack = state.stack;
		const int * md_list = mbedtls_md_list();
		stack->newTable();
		for (int i = 1, mdType = *md_list; md_list != 0 && mdType != 0; mdType = *md_list, i++, md_list++){
			stack->push<int>(i);
			stack->push<int>(mdType);
			stack->setTable(-3);
		}
		return 1;
	}

	int mdInfo(State & state){
		Stack * stack = state.stack;
		MDinfo * interfaceMDinfo = OBJECT_IFACE(MDinfo);
		if (stack->is<LUA_TNUMBER>(1) || stack->is<LUA_TSTRING>(1)){
			const mbedtls_md_info_t * info = nullptr;

			if (stack->is<LUA_TNUMBER>(1)){
				std::string name = stack->to<const std::string>(1);
				info = mbedtls_md_info_from_type(static_cast<mbedtls_md_type_t>(stack->to<int>(1)));
			}
			else
				if (stack->is<LUA_TSTRING>(1)){
					std::string name = stack->to<const std::string>(1);
					info = mbedtls_md_info_from_string(name.c_str());
				}

			if (info){
				interfaceMDinfo->push(const_cast<mbedtls_md_info_t *>(info));
			}
			else{
				stack->push<bool>(false);
			}
			return 1;
		}
		return 0;
	}

	void initMDContext(State * state, Module & module){
		INIT_OBJECT(MDContext);
		module["md"] = md;
		module["mdFile"] = mdFile;
		module["mdList"] = mdList;
		module["mdInfo"] = mdInfo;
	}
};
