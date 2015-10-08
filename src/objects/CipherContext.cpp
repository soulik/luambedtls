#include "objects/CipherContext.hpp"
#include "objects/CipherInfo.hpp"

namespace luambedtls {
	mbedtls_cipher_context_t * CipherContext::constructor(State & state, bool & managed){
		mbedtls_cipher_context_t * context = new mbedtls_cipher_context_t;
		mbedtls_cipher_init(context);
		return context;
	}

	void CipherContext::destructor(State & state, mbedtls_cipher_context_t * context){
		mbedtls_cipher_free(context);
		delete context;
	}

	int CipherContext::setup(State & state, mbedtls_cipher_context_t * context){
		Stack * stack = state.stack;
		CipherInfo * interfaceCipherInfo = OBJECT_IFACE(CipherInfo);
		const mbedtls_cipher_info_t * info = interfaceCipherInfo->get(1);
		if (info){
			stack->push<int>(mbedtls_cipher_setup(context, info));
			return 1;
		}
		return 0;
	}

	int CipherContext::getBlockSize(State & state, mbedtls_cipher_context_t * context){
		Stack * stack = state.stack;
		stack->push<int>(mbedtls_cipher_get_block_size(context));
		return 1;
	}
	int CipherContext::getIVSize(State & state, mbedtls_cipher_context_t * context) {
		Stack * stack = state.stack;
		stack->push<int>(mbedtls_cipher_get_iv_size(context));
		return 1;
	}
	int CipherContext::getType(State & state, mbedtls_cipher_context_t * context){
		Stack * stack = state.stack;
		stack->push<int>(mbedtls_cipher_get_type(context));
		return 1;
	}
	int CipherContext::getName(State & state, mbedtls_cipher_context_t * context){
		Stack * stack = state.stack;
		stack->push<const std::string &>(mbedtls_cipher_get_name(context));
		return 1;
	}
	int CipherContext::getKeyLen(State & state, mbedtls_cipher_context_t * context){
		Stack * stack = state.stack;
		stack->push<int>(mbedtls_cipher_get_key_bitlen(context));
		return 1;
	}
	int CipherContext::getOperation(State & state, mbedtls_cipher_context_t * context){
		Stack * stack = state.stack;
		stack->push<int>(mbedtls_cipher_get_operation(context));
		return 1;
	}

	int CipherContext::setKey(State & state, mbedtls_cipher_context_t * context){
		Stack * stack = state.stack;
		if (stack->is<LUA_TSTRING>(1) && stack->is<LUA_TNUMBER>(2)){
			const std::string key = stack->toLString(1);
			int bitLen = key.length() * 8;
			mbedtls_operation_t operation = static_cast<mbedtls_operation_t>(stack->to<int>(2));
			stack->push<int>(mbedtls_cipher_setkey(context, reinterpret_cast<const unsigned char*>(key.c_str()), bitLen, operation));
			return 1;
		}
		return 0;
	}
	int CipherContext::setPaddingMode(State & state, mbedtls_cipher_context_t * context){
		Stack * stack = state.stack;
		if (stack->is<LUA_TNUMBER>(1)){
			mbedtls_cipher_padding_t mode = static_cast<mbedtls_cipher_padding_t>(stack->to<int>(1));
			mbedtls_cipher_set_padding_mode(context, mode);
			return 0;
		}
		return 0;
	}
	int CipherContext::setIV(State & state, mbedtls_cipher_context_t * context){
		Stack * stack = state.stack;
		if (stack->is<LUA_TSTRING>(1)){
			const std::string iv = stack->toLString(1);
			stack->push<int>(mbedtls_cipher_set_iv(context, reinterpret_cast<const unsigned char*>(iv.c_str()), iv.length()));
			return 1;
		}
		return 0;
	}

	int CipherContext::reset(State & state, mbedtls_cipher_context_t * context){
		Stack * stack = state.stack;
		stack->push<int>(mbedtls_cipher_reset(context));
		return 1;
	}
	int CipherContext::updateAD(State & state, mbedtls_cipher_context_t * context){
		Stack * stack = state.stack;
		if (stack->is<LUA_TSTRING>(1)){
			const std::string ad = stack->toLString(1);
			stack->push<int>(mbedtls_cipher_update_ad(context, reinterpret_cast<const unsigned char*>(ad.c_str()), ad.length()));
			return 1;
		}
		return 0;
	}
	int CipherContext::update(State & state, mbedtls_cipher_context_t * context){
		Stack * stack = state.stack;
		if (stack->is<LUA_TSTRING>(1) && stack->is<LUA_TNUMBER>(2)){
			const std::string input = stack->toLString(1);
			size_t outputSize = stack->to<int>(2);
			unsigned char * output = new unsigned char[outputSize];

			int result = mbedtls_cipher_update(context,
				reinterpret_cast<const unsigned char*>(input.c_str()), input.length(),
				output, &outputSize
			);
			if (result == 0){
				stack->pushLString(std::string(reinterpret_cast<char*>(output), outputSize));
			}
			else{
				stack->push<int>(result);
			}
			return 1;
		}
		return 0;
	}
	int CipherContext::finish(State & state, mbedtls_cipher_context_t * context){
		Stack * stack = state.stack;
		if (stack->is<LUA_TNUMBER>(1)){
			size_t outputSize = stack->to<int>(1);
			unsigned char * output = new unsigned char[outputSize];

			int result = mbedtls_cipher_finish(context,	output, &outputSize);
			if (result == 0){
				stack->pushLString(std::string(reinterpret_cast<char*>(output), outputSize));
			}
			else{
				stack->push<int>(result);
			}
			return 1;
		}
		return 0;
	}
	int CipherContext::writeTag(State & state, mbedtls_cipher_context_t * context){
		Stack * stack = state.stack;
		if (stack->is<LUA_TNUMBER>(1)){
			size_t outputSize = stack->to<int>(1);
			unsigned char * tag = new unsigned char[outputSize];

			int result = mbedtls_cipher_write_tag(context, tag, outputSize);
			if (result == 0){
				stack->pushLString(std::string(reinterpret_cast<char*>(tag), outputSize));
			}
			else{
				stack->push<int>(result);
			}
			return 1;
		}
		return 0;
	}
	int CipherContext::checkTag(State & state, mbedtls_cipher_context_t * context){
		Stack * stack = state.stack;
		if (stack->is<LUA_TSTRING>(1)){
			const std::string tag = stack->toLString(1);

			stack->push<int>(mbedtls_cipher_check_tag(context, reinterpret_cast<const unsigned char*>(tag.c_str()), tag.length()));
			return 1;
		}
		return 0;
	}
	int CipherContext::crypt(State & state, mbedtls_cipher_context_t * context){
		Stack * stack = state.stack;
		if (stack->is<LUA_TSTRING>(1) && stack->is<LUA_TSTRING>(2) && stack->is<LUA_TNUMBER>(3)){
			const std::string iv = stack->toLString(1);
			const std::string input = stack->toLString(2);
			size_t outputSize = stack->to<int>(3);
			unsigned char * output = new unsigned char[outputSize];

			int result = mbedtls_cipher_crypt(context,
				reinterpret_cast<const unsigned char*>(iv.c_str()), iv.length(),
				reinterpret_cast<const unsigned char*>(input.c_str()), input.length(),
				output, &outputSize
				);
			if (result == 0){
				stack->pushLString(std::string(reinterpret_cast<char*>(output), outputSize));
			}
			else{
				stack->push<int>(result);
			}
			return 1;
		}
		return 0;
	}
	int CipherContext::authEncrypt(State & state, mbedtls_cipher_context_t * context){
		Stack * stack = state.stack;
		if (stack->is<LUA_TSTRING>(1) && stack->is<LUA_TSTRING>(2) && stack->is<LUA_TNUMBER>(3) && stack->is<LUA_TNUMBER>(4)){
			const std::string iv = stack->toLString(1);
			const std::string input = stack->toLString(2);

			size_t outputSize = stack->to<int>(3);
			unsigned char * output = new unsigned char[outputSize];

			size_t tagSize = stack->to<int>(4);
			unsigned char * tag = new unsigned char[tagSize];
			int result = -1;

			if (stack->is<LUA_TSTRING>(5)){
				const std::string ad = stack->toLString(5);
				result = mbedtls_cipher_auth_encrypt(context,
					reinterpret_cast<const unsigned char*>(iv.c_str()), iv.length(),
					reinterpret_cast<const unsigned char*>(ad.c_str()), ad.length(),
					reinterpret_cast<const unsigned char*>(input.c_str()), input.length(),
					output, &outputSize,
					tag, tagSize
				);
			}
			else{
				result = mbedtls_cipher_auth_encrypt(context,
					reinterpret_cast<const unsigned char*>(iv.c_str()), iv.length(),
					nullptr, 0,
					reinterpret_cast<const unsigned char*>(input.c_str()), input.length(),
					output, &outputSize,
					tag, tagSize
					);
			}

			if (result == 0){
				stack->pushLString(std::string(reinterpret_cast<char*>(output), outputSize));
				stack->pushLString(std::string(reinterpret_cast<char*>(tag), tagSize));
				delete[] output;
				delete[] tag;
				return 2;
			}
			else{
				stack->push<int>(result);
				return 1;
			}
		}
		return 0;
	}
	int CipherContext::authDecrypt(State & state, mbedtls_cipher_context_t * context){
		Stack * stack = state.stack;
		if (stack->is<LUA_TSTRING>(1) && stack->is<LUA_TSTRING>(2) && stack->is<LUA_TSTRING>(3) && stack->is<LUA_TNUMBER>(4)){
			const std::string iv = stack->toLString(1);
			const std::string input = stack->toLString(2);
			const std::string tag = stack->toLString(3);

			size_t outputSize = stack->to<int>(4);
			unsigned char * output = new unsigned char[outputSize];

			int result = -1;

			if (stack->is<LUA_TSTRING>(5)){
				const std::string ad = stack->toLString(5);
				result = mbedtls_cipher_auth_decrypt(context,
					reinterpret_cast<const unsigned char*>(iv.c_str()), iv.length(),
					reinterpret_cast<const unsigned char*>(ad.c_str()), ad.length(),
					reinterpret_cast<const unsigned char*>(input.c_str()), input.length(),
					output, &outputSize,
					reinterpret_cast<const unsigned char*>(tag.c_str()), tag.length()
					);
			}
			else{
				result = mbedtls_cipher_auth_decrypt(context,
					reinterpret_cast<const unsigned char*>(iv.c_str()), iv.length(),
					nullptr, 0,
					reinterpret_cast<const unsigned char*>(input.c_str()), input.length(),
					output, &outputSize,
					reinterpret_cast<const unsigned char*>(tag.c_str()), tag.length()
					);
			}

			if (result == 0){
				stack->pushLString(std::string(reinterpret_cast<char*>(output), outputSize));
				delete[] output;
			}
			else{
				stack->push<int>(result);
			}
			return 1;
		}
		return 0;
	}

	int cipherList(State & state){
		Stack * stack = state.stack;
		CipherInfo * interfaceCipherInfo = OBJECT_IFACE(CipherInfo);
		const int * list = mbedtls_cipher_list();
		stack->newTable();

		while (*list != 0){
			const mbedtls_cipher_info_t * info = mbedtls_cipher_info_from_type(static_cast<mbedtls_cipher_type_t>(*list));
			stack->push<int>(*list);
			interfaceCipherInfo->push(const_cast<mbedtls_cipher_info_t *>(info));
			stack->setTable();
			list++;
		}
		return 1;
	}

	int cipherInfo(State & state){
		Stack * stack = state.stack;
		CipherInfo * interfaceCipherInfo = OBJECT_IFACE(CipherInfo);
		mbedtls_cipher_info_t * info = nullptr;
		if (stack->is<LUA_TNUMBER>(1)){
			mbedtls_cipher_type_t type = static_cast<mbedtls_cipher_type_t>(stack->to<int>(1));
			info = const_cast<mbedtls_cipher_info_t*>(mbedtls_cipher_info_from_type(type));
		}
		else if (stack->is<LUA_TSTRING>(1)){
			const std::string name = stack->to<const std::string>(1);
			info = const_cast<mbedtls_cipher_info_t*>(mbedtls_cipher_info_from_string(name.c_str()));
		}
		if (info){
			interfaceCipherInfo->push(info);
			return 1;
		}
		else{
			return 0;
		}
	}

	void initCipherContext(State * state, Module & module){
		INIT_OBJECT(CipherContext);
		module["cipherList"] = cipherList;
		module["cipherInfo"] = cipherInfo;
	}
};
