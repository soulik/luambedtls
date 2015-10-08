#include "objects/PKContext.hpp"
#include "objects/RSAContext.hpp"
#include "objects/ECPKeyPair.hpp"
#include "objects/CTRDRBGContext.hpp"
#include "objects/PKinfo.hpp"

namespace luambedtls {
	mbedtls_pk_context * PKContext::constructor(State & state, bool & managed){
		mbedtls_pk_context * context = new mbedtls_pk_context;
		mbedtls_pk_init(context);
		return context;
	}

	void PKContext::destructor(State & state, mbedtls_pk_context * context){
		mbedtls_pk_free(context);
		delete context;
	}

	int PKContext::getRSA(State & state, mbedtls_pk_context * context){
		Stack * stack = state.stack;
		RSAContext * interfaceRSA = OBJECT_IFACE(RSAContext);
		mbedtls_rsa_context * rsa = mbedtls_pk_rsa(*context);
		if (rsa){
			interfaceRSA->push(rsa);
			return 1;
		}
		else{
			return 0;
		}
	}

	int PKContext::getEC(State & state, mbedtls_pk_context * context){
		Stack * stack = state.stack;
		ECPKeyPair * interfaceECPKeyPair = OBJECT_IFACE(ECPKeyPair);
		mbedtls_ecp_keypair * ec = mbedtls_pk_ec(*context);
		if (ec){
			interfaceECPKeyPair->push(ec);
			return 1;
		}
		else{
			return 0;
		}
	}

	int PKContext::getType(State & state, mbedtls_pk_context * context){
		Stack * stack = state.stack;
		stack->push<int>(mbedtls_pk_get_type(context));
		return 1;
	}
	int PKContext::getName(State & state, mbedtls_pk_context * context){
		Stack * stack = state.stack;
		stack->push<const std::string &>(mbedtls_pk_get_name(context));
		return 1;
	}
	int PKContext::getBitLen(State & state, mbedtls_pk_context * context){
		Stack * stack = state.stack;
		stack->push<int>(mbedtls_pk_get_bitlen(context));
		return 1;
	}
	int PKContext::getLength(State & state, mbedtls_pk_context * context){
		Stack * stack = state.stack;
		stack->push<int>(mbedtls_pk_get_len(context));
		return 1;
	}

	int PKContext::setup(State & state, mbedtls_pk_context * context){
		Stack * stack = state.stack;
		PKinfo * interfacePKinfo = OBJECT_IFACE(PKinfo);
		mbedtls_pk_info_t * info = interfacePKinfo->get(1);
		if (info){
			stack->push<int>(mbedtls_pk_setup(context, info));
			return 1;
		}
		return 0;
	}
	
	int PKContext::canDo(State & state, mbedtls_pk_context * context){
		Stack * stack = state.stack;
		if (stack->is<LUA_TNUMBER>(1)){
			stack->push<bool>(mbedtls_pk_can_do(context, static_cast<mbedtls_pk_type_t>(stack->to<int>(1))) == 1);
			return 1;
		}
		return 0;
	}
	int PKContext::verify(State & state, mbedtls_pk_context * context){
		Stack * stack = state.stack;
		if (stack->is<LUA_TNUMBER>(1) && stack->is<LUA_TSTRING>(2) && stack->is<LUA_TSTRING>(3)){
			mbedtls_md_type_t MDType = static_cast<mbedtls_md_type_t>(stack->to<int>(1));
			const std::string hash = stack->toLString(2);
			const std::string sig = stack->toLString(3);
			stack->push<int>(mbedtls_pk_verify(context, MDType, reinterpret_cast<const unsigned char *>(hash.c_str()), hash.length(), reinterpret_cast<const unsigned char *>(sig.c_str()), sig.length()));
			return 1;
		}
		return 0;
	}
	int PKContext::verifyExt(State & state, mbedtls_pk_context * context){
		Stack * stack = state.stack;
		if (stack->is<LUA_TNUMBER>(1) && stack->is<LUA_TNUMBER>(2) && stack->is<LUA_TSTRING>(3) && stack->is<LUA_TSTRING>(4)){
			mbedtls_pk_type_t PKType = static_cast<mbedtls_pk_type_t>(stack->to<int>(1));
			mbedtls_md_type_t MDType = static_cast<mbedtls_md_type_t>(stack->to<int>(2));
			const std::string hash = stack->toLString(3);
			const std::string sig = stack->toLString(4);

			if (PKType == MBEDTLS_PK_RSASSA_PSS){
				if (stack->is<LUA_TTABLE>(5)){
					mbedtls_pk_rsassa_pss_options options;
					stack->getField("hashID", 5);
					stack->getField("expectedSaltLen", 5);

					if (stack->is<LUA_TNUMBER>(-1)){
						options.expected_salt_len = stack->to<int>(-1);
					}
					if (stack->is<LUA_TNUMBER>(-2)){
						options.mgf1_hash_id = static_cast<mbedtls_md_type_t>(stack->to<int>(-2));
					}
					stack->pop(2);

					stack->push<int>(mbedtls_pk_verify_ext(PKType, &options, context, MDType, reinterpret_cast<const unsigned char *>(hash.c_str()), hash.length(), reinterpret_cast<const unsigned char *>(sig.c_str()), sig.length()));
				}
				else{
					return 0;
				}
			}
			else{
				stack->push<int>(mbedtls_pk_verify_ext(PKType, nullptr, context, MDType, reinterpret_cast<const unsigned char *>(hash.c_str()), hash.length(), reinterpret_cast<const unsigned char *>(sig.c_str()), sig.length()));
			}
			return 1;
		}
		return 0;
	}
	int PKContext::sign(State & state, mbedtls_pk_context * context){
		Stack * stack = state.stack;
		CTRDRBGContext * interfaceCTRDRBGContext = OBJECT_IFACE(CTRDRBGContext);
		mbedtls_ctr_drbg_context * drbg = interfaceCTRDRBGContext->get(1);

		if (drbg, stack->is<LUA_TNUMBER>(2) && stack->is<LUA_TSTRING>(3) && stack->is<LUA_TNUMBER>(4)){
			mbedtls_md_type_t MDType = static_cast<mbedtls_md_type_t>(stack->to<int>(2));
			const std::string hash = stack->toLString(3);
			
			size_t outputLen = stack->to<int>(4);
			unsigned char * sign = new unsigned char[outputLen];

			int result = mbedtls_pk_sign(context, MDType,
				reinterpret_cast<const unsigned char *>(hash.c_str()), hash.length(),
				sign, &outputLen, mbedtls_ctr_drbg_random, drbg);

			if (result == 0){
				stack->pushLString(std::string(reinterpret_cast<char*>(sign), outputLen));
			}
			else{
				stack->push<int>(result);
			}
			delete[] sign;
			return 1;
		}
		return 0;
	}
	int PKContext::decrypt(State & state, mbedtls_pk_context * context){
		Stack * stack = state.stack;
		stack->push<int>(context->pk_info->type);
		CTRDRBGContext * interfaceCTRDRBGContext = OBJECT_IFACE(CTRDRBGContext);
		mbedtls_ctr_drbg_context * drbg = interfaceCTRDRBGContext->get(1);

		if (drbg && stack->is<LUA_TSTRING>(2) && stack->is<LUA_TNUMBER>(3)){
			const std::string input = stack->toLString(2);
			
			size_t outputSize = stack->to<int>(3);
			size_t outputLen = outputSize;
			unsigned char * output = new unsigned char[outputSize];

			int result = mbedtls_pk_decrypt(context,
				reinterpret_cast<const unsigned char *>(input.c_str()), input.length(),
				output, &outputLen, outputSize,
				mbedtls_ctr_drbg_random, drbg);
			if (result == 0){
				stack->pushLString(std::string(reinterpret_cast<char*>(output), outputLen));
			}
			else{
				stack->push<int>(result);
			}
			delete[] output;
			return 1;
		}
		return 0;
	}
	int PKContext::encrypt(State & state, mbedtls_pk_context * context){
		Stack * stack = state.stack;
		stack->push<int>(context->pk_info->type);
		CTRDRBGContext * interfaceCTRDRBGContext = OBJECT_IFACE(CTRDRBGContext);
		mbedtls_ctr_drbg_context * drbg = interfaceCTRDRBGContext->get(1);

		if (drbg && stack->is<LUA_TSTRING>(2) && stack->is<LUA_TNUMBER>(3)){
			const std::string input = stack->toLString(2);

			size_t outputSize = stack->to<int>(3);
			size_t outputLen = outputSize;
			unsigned char * output = new unsigned char[outputSize];

			int result = mbedtls_pk_encrypt(context,
				reinterpret_cast<const unsigned char *>(input.c_str()), input.length(),
				output, &outputLen, outputSize,
				mbedtls_ctr_drbg_random, drbg);
			if (result == 0){
				stack->pushLString(std::string(reinterpret_cast<char*>(output), outputLen));
			}
			else{
				stack->push<int>(result);
			}
			delete[] output;
			return 1;
		}
		return 0;
	}
	int PKContext::checkPair(State & state, mbedtls_pk_context * context){
		Stack * stack = state.stack;
		PKContext * interfacePK = OBJECT_IFACE(PKContext);
		mbedtls_pk_context * privKey = interfacePK->get(1);
		if (privKey){
			stack->push<int>(mbedtls_pk_check_pair(context, privKey));
			return 1;
		}
		return 0;
	}
	int PKContext::parseKey(State & state, mbedtls_pk_context * context){
		Stack * stack = state.stack;
		if (stack->is<LUA_TSTRING>(1)){
			const std::string key = stack->toLString(1);

			if (stack->is<LUA_TSTRING>(2)){
				const std::string pwd = stack->toLString(2);
				stack->push<int>(mbedtls_pk_parse_key(context,
					reinterpret_cast<const unsigned char *>(key.c_str()), key.length(),
					reinterpret_cast<const unsigned char *>(pwd.c_str()), pwd.length()
					));
			}
			else{
				stack->push<int>(mbedtls_pk_parse_key(context,
					reinterpret_cast<const unsigned char *>(key.c_str()), key.length(),
					nullptr, 0
					));
			}

			return 1;
		}
		return 0;
	}
	int PKContext::parsePublicKey(State & state, mbedtls_pk_context * context){
		Stack * stack = state.stack;
		if (stack->is<LUA_TSTRING>(1)){
			const std::string key = stack->toLString(1);

			stack->push<int>(mbedtls_pk_parse_public_key(context,
				reinterpret_cast<const unsigned char *>(key.c_str()), key.length()
				));
			return 1;
		}
		return 0;
	}
	int PKContext::parseKeyFile(State & state, mbedtls_pk_context * context){
		Stack * stack = state.stack;
		if (stack->is<LUA_TSTRING>(1)){
			const std::string keyFile = stack->to<const std::string>(1);

			if (stack->is<LUA_TSTRING>(2)){
				const std::string pwd = stack->to<const std::string>(2);
				stack->push<int>(mbedtls_pk_parse_keyfile(context, keyFile.c_str(), pwd.c_str()));
			}
			else{
				stack->push<int>(mbedtls_pk_parse_keyfile(context, keyFile.c_str(), nullptr));
			}

			return 1;
		}
		return 0;
	}
	int PKContext::parsePublicKeyFile(State & state, mbedtls_pk_context * context){
		Stack * stack = state.stack;
		if (stack->is<LUA_TSTRING>(1)){
			const std::string keyFile = stack->to<const std::string>(1);

			stack->push<int>(mbedtls_pk_parse_public_keyfile(context, keyFile.c_str()));
			return 1;
		}
		return 0;
	}
	int PKContext::writeKeyDER(State & state, mbedtls_pk_context * context){
		Stack * stack = state.stack;
		if (stack->is<LUA_TNUMBER>(1)){
			size_t size = stack->to<int>(1);
			unsigned char * output = new unsigned char[size];
			int result = mbedtls_pk_write_key_der(context, output, size);
			if (result == 0){
				stack->pushLString(std::string(reinterpret_cast<char*>(output), size));
			}
			else{
				stack->push<int>(result);
			}
			delete[] output;
			return 1;
		}
		return 0;
	}
	int PKContext::writePublicKeyDER(State & state, mbedtls_pk_context * context){
		Stack * stack = state.stack;
		if (stack->is<LUA_TNUMBER>(1)){
			size_t size = stack->to<int>(1);
			unsigned char * output = new unsigned char[size];
			int result = mbedtls_pk_write_pubkey_der(context, output, size);
			if (result == 0){
				stack->pushLString(std::string(reinterpret_cast<char*>(output), size));
			}
			else{
				stack->push<int>(result);
			}
			delete[] output;
			return 1;
		}
		return 0;
	}
	int PKContext::writeKeyPEM(State & state, mbedtls_pk_context * context){
		Stack * stack = state.stack;
		if (stack->is<LUA_TNUMBER>(1)){
			size_t size = stack->to<int>(1);
			unsigned char * output = new unsigned char[size];
			int result = mbedtls_pk_write_key_pem(context, output, size);
			if (result == 0){
				stack->pushLString(std::string(reinterpret_cast<char*>(output), size));
			}
			else{
				stack->push<int>(result);
			}
			delete[] output;
			return 1;
		}
		return 0;
	}
	int PKContext::writePublicKeyPEM(State & state, mbedtls_pk_context * context){
		Stack * stack = state.stack;
		if (stack->is<LUA_TNUMBER>(1)){
			size_t size = stack->to<int>(1);
			unsigned char * output = new unsigned char[size];
			int result = mbedtls_pk_write_pubkey_pem(context, output, size);
			if (result == 0){
				stack->pushLString(std::string(reinterpret_cast<char*>(output), size));
			}
			else{
				stack->push<int>(result);
			}
			delete[] output;
			return 1;
		}
		return 0;
	}
	int PKContext::parseSubPublicKey(State & state, mbedtls_pk_context * context){
		Stack * stack = state.stack;
		return 0;
	}
	int PKContext::writePublicKey(State & state, mbedtls_pk_context * context){
		Stack * stack = state.stack;
		return 0;
	}
	int PKContext::loadFile(State & state, mbedtls_pk_context * context){
		Stack * stack = state.stack;
		return 0;
	}

	


	void initPKContext(State * state, Module & module){
		INIT_OBJECT(PKContext);
	}
};
