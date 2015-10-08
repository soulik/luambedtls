#include "objects/RSAContext.hpp"
#include "objects/CTRDRBGContext.hpp"
#include "objects/MPI.hpp"

namespace luambedtls {

#define PUSH_MPI(VALUE) Stack * stack = state.stack; MPI * interfaceMPI = OBJECT_IFACE(MPI); interfaceMPI->push(&context->VALUE); return 1
#define READ_MPI(VALUE) Stack * stack = state.stack; MPI * interfaceMPI = OBJECT_IFACE(MPI); mbedtls_mpi * value = interfaceMPI->get(1); if (value) mbedtls_mpi_copy(&context->VALUE, value); return 0

	mbedtls_rsa_context * RSAContext::constructor(State & state, bool & managed){
		Stack * stack = state.stack;
		if (stack->is<LUA_TNUMBER>(1) && stack->is<LUA_TNUMBER>(2)){
			mbedtls_rsa_context * context = new mbedtls_rsa_context;
			int padding = stack->to<int>(1);
			int hashID = stack->to<int>(2);
			mbedtls_rsa_init(context, padding, hashID);
			return context;
		}else{
			return nullptr;
		}
	}

	void RSAContext::destructor(State & state, mbedtls_rsa_context * context){
		mbedtls_rsa_free(context);
		delete context;
	}

	int RSAContext::copy(State & state, mbedtls_rsa_context * context){
		Stack * stack = state.stack;
		RSAContext * interfaceRSA = OBJECT_IFACE(RSAContext);
		mbedtls_rsa_context * newContext = nullptr;

		if (stack->getTop() > 0){
			newContext = interfaceRSA->get(1);
		}
		else{
			newContext = new mbedtls_rsa_context;
		}

		if (newContext){
			int result = mbedtls_rsa_copy(newContext, context);
			if (result == 0){
				interfaceRSA->push(newContext, true);
			}
			else{
				delete newContext;
				stack->push<int>(result);
			}
			return 1;
		}
		return 0;
	}

	int RSAContext::setPadding(State & state, mbedtls_rsa_context * context){
		Stack * stack = state.stack;
		if (stack->is<LUA_TNUMBER>(1) && stack->is<LUA_TNUMBER>(2)){
			int padding = stack->to<int>(1);
			int hashID = stack->to<int>(2);
			mbedtls_rsa_set_padding(context, padding, hashID);
		}
		return 0;
	}
	int RSAContext::genKey(State & state, mbedtls_rsa_context * context){
		Stack * stack = state.stack;
		CTRDRBGContext * interfaceCTRDRBGContext = OBJECT_IFACE(CTRDRBGContext);
		mbedtls_ctr_drbg_context * drbg = interfaceCTRDRBGContext->get(1);
		if (drbg && stack->is<LUA_TNUMBER>(2) && stack->is<LUA_TNUMBER>(3)){
			unsigned int nbits = static_cast<unsigned int>(stack->to<LUA_NUMBER>(2));
			int exponent = stack->to<int>(3);
			stack->push<int>(mbedtls_rsa_gen_key(context, mbedtls_ctr_drbg_random, drbg, nbits, exponent));
			return 1;
		}
		return 0;
	}
	int RSAContext::checkPubKey(State & state, mbedtls_rsa_context * context){
		Stack * stack = state.stack;
		stack->push<int>(mbedtls_rsa_check_pubkey(context));
		return 1;
	}
	int RSAContext::checkPrivKey(State & state, mbedtls_rsa_context * context){
		Stack * stack = state.stack;
		stack->push<int>(mbedtls_rsa_check_privkey(context));
		return 1;
	}
	int RSAContext::checkPubPriv(State & state, mbedtls_rsa_context * context){
		Stack * stack = state.stack;
		RSAContext * interfaceRSA = OBJECT_IFACE(RSAContext);
		mbedtls_rsa_context * privContext = interfaceRSA->get(1);
		if (privContext){
			stack->push<int>(mbedtls_rsa_check_pub_priv(context, privContext));
			return 1;
		}
		else{
			return 0;
		}
	}
	int RSAContext::publicKeyOp(State & state, mbedtls_rsa_context * context){
		Stack * stack = state.stack;
		if (stack->is<LUA_TSTRING>(1)){
			const std::string input = stack->to<const std::string>(1);
			unsigned char * output = new unsigned char[context->len];
			int result = mbedtls_rsa_public(context, reinterpret_cast<const unsigned char *>(input.c_str()), output);
			if (result == 0){
				stack->pushLString(std::string(reinterpret_cast<char*>(output), context->len));
			}
			else{
				stack->push<int>(result);
			}
			delete[] output;
			return 1;
		}
		return 0;
	}
	int RSAContext::privateKeyOp(State & state, mbedtls_rsa_context * context){
		Stack * stack = state.stack;
		CTRDRBGContext * interfaceCTRDRBGContext = OBJECT_IFACE(CTRDRBGContext);
		mbedtls_ctr_drbg_context * drbg = interfaceCTRDRBGContext->get(1);

		if (drbg && stack->is<LUA_TSTRING>(2)){
			const std::string input = stack->to<const std::string>(2);
			unsigned char * output = new unsigned char[context->len];
			int result = mbedtls_rsa_private(context, mbedtls_ctr_drbg_random, drbg, reinterpret_cast<const unsigned char *>(input.c_str()), output);
			if (result == 0){
				stack->pushLString(std::string(reinterpret_cast<char*>(output), context->len));
			}
			else{
				stack->push<int>(result);
			}
			delete[] output;
			return 1;
		}
		return 0;
	}

	int RSAContext::encryptPKCS1(State & state, mbedtls_rsa_context * context){
		Stack * stack = state.stack;
		CTRDRBGContext * interfaceCTRDRBGContext = OBJECT_IFACE(CTRDRBGContext);
		mbedtls_ctr_drbg_context * drbg = interfaceCTRDRBGContext->get(1);

		if (drbg && stack->is<LUA_TNUMBER>(2) && stack->is<LUA_TSTRING>(3)){
			int mode = stack->to<int>(2);
			const std::string input = stack->toLString(3);
			const size_t outputLen = mbedtls_mpi_size(&context->N);
			unsigned char * output = new unsigned char[outputLen];
			int result = mbedtls_rsa_pkcs1_encrypt(context, mbedtls_ctr_drbg_random, drbg, mode, input.length(), reinterpret_cast<const unsigned char *>(input.c_str()), output);
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
	int RSAContext::encryptRSAESPKCS1v15(State & state, mbedtls_rsa_context * context){
		Stack * stack = state.stack;
		CTRDRBGContext * interfaceCTRDRBGContext = OBJECT_IFACE(CTRDRBGContext);
		mbedtls_ctr_drbg_context * drbg = interfaceCTRDRBGContext->get(1);

		if (drbg && stack->is<LUA_TNUMBER>(2) && stack->is<LUA_TSTRING>(3)){
			int mode = stack->to<int>(2);
			const std::string input = stack->toLString(3);
			const size_t outputLen = mbedtls_mpi_size(&context->N);
			unsigned char * output = new unsigned char[outputLen];
			int result = mbedtls_rsa_rsaes_pkcs1_v15_encrypt(context, mbedtls_ctr_drbg_random, drbg, mode, input.length(), reinterpret_cast<const unsigned char *>(input.c_str()), output);
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
	int RSAContext::encryptRSAESOAEP(State & state, mbedtls_rsa_context * context){
		Stack * stack = state.stack;
		CTRDRBGContext * interfaceCTRDRBGContext = OBJECT_IFACE(CTRDRBGContext);
		mbedtls_ctr_drbg_context * drbg = interfaceCTRDRBGContext->get(1);

		if (drbg && stack->is<LUA_TNUMBER>(2) && stack->is<LUA_TSTRING>(3) && stack->is<LUA_TSTRING>(4)){
			int mode = stack->to<int>(2);
			const std::string input = stack->toLString(3);
			const std::string label = stack->toLString(4);

			const size_t outputLen = mbedtls_mpi_size(&context->N);
			unsigned char * output = new unsigned char[outputLen];
			int result = mbedtls_rsa_rsaes_oaep_encrypt(context, mbedtls_ctr_drbg_random, drbg, mode,
				reinterpret_cast<const unsigned char *>(label.c_str()), label.length(),
				input.length(), reinterpret_cast<const unsigned char *>(input.c_str()), output);
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
	int RSAContext::decryptPKCS1(State & state, mbedtls_rsa_context * context){
		Stack * stack = state.stack;
		CTRDRBGContext * interfaceCTRDRBGContext = OBJECT_IFACE(CTRDRBGContext);
		mbedtls_ctr_drbg_context * drbg = interfaceCTRDRBGContext->get(1);

		if (drbg && stack->is<LUA_TNUMBER>(2) && stack->is<LUA_TSTRING>(3) && stack->is<LUA_TNUMBER>(4)){
			int mode = stack->to<int>(2);
			const std::string input = stack->toLString(3);
			size_t outputMaxLen = stack->to<int>(4);
			size_t plainTextLength = 0;

			const size_t outputLen = mbedtls_mpi_size(&context->N);
			unsigned char * output = new unsigned char[outputLen];

			int result = mbedtls_rsa_pkcs1_decrypt(context, mbedtls_ctr_drbg_random, drbg, mode, &plainTextLength, reinterpret_cast<const unsigned char *>(input.c_str()), output, outputMaxLen);
			if (result == 0){
				stack->pushLString(std::string(reinterpret_cast<char*>(output), plainTextLength));
			}
			else{
				stack->push<int>(result);
			}
			delete[] output;
			return 1;
		}
		return 0;
	}
	int RSAContext::decryptRSAESPKCS1v15(State & state, mbedtls_rsa_context * context){
		Stack * stack = state.stack;
		CTRDRBGContext * interfaceCTRDRBGContext = OBJECT_IFACE(CTRDRBGContext);
		mbedtls_ctr_drbg_context * drbg = interfaceCTRDRBGContext->get(1);

		if (drbg && stack->is<LUA_TNUMBER>(2) && stack->is<LUA_TSTRING>(3) && stack->is<LUA_TNUMBER>(4)){
			int mode = stack->to<int>(2);
			const std::string input = stack->toLString(3);
			size_t outputMaxLen = stack->to<int>(4);
			size_t plainTextLength = 0;

			const size_t outputLen = mbedtls_mpi_size(&context->N);
			unsigned char * output = new unsigned char[outputLen];

			int result = mbedtls_rsa_rsaes_pkcs1_v15_decrypt(context, mbedtls_ctr_drbg_random, drbg, mode, &plainTextLength, reinterpret_cast<const unsigned char *>(input.c_str()), output, outputMaxLen);
			if (result == 0){
				stack->pushLString(std::string(reinterpret_cast<char*>(output), plainTextLength));
			}
			else{
				stack->push<int>(result);
			}
			delete[] output;
			return 1;
		}
		return 0;
	}
	int RSAContext::decryptRSAESOAEP(State & state, mbedtls_rsa_context * context){
		Stack * stack = state.stack;
		CTRDRBGContext * interfaceCTRDRBGContext = OBJECT_IFACE(CTRDRBGContext);
		mbedtls_ctr_drbg_context * drbg = interfaceCTRDRBGContext->get(1);

		if (drbg && stack->is<LUA_TNUMBER>(2) && stack->is<LUA_TSTRING>(3) && stack->is<LUA_TSTRING>(4) && stack->is<LUA_TNUMBER>(5)){
			int mode = stack->to<int>(2);
			const std::string input = stack->toLString(3);
			const std::string label = stack->toLString(4);
			size_t outputMaxLen = stack->to<int>(5);
			size_t plainTextLength = 0;

			const size_t outputLen = mbedtls_mpi_size(&context->N);
			unsigned char * output = new unsigned char[outputLen];

			int result = mbedtls_rsa_rsaes_oaep_decrypt(context, mbedtls_ctr_drbg_random, drbg, mode,
				reinterpret_cast<const unsigned char *>(label.c_str()), label.length(),
				&plainTextLength, reinterpret_cast<const unsigned char *>(input.c_str()), output, outputMaxLen);
			if (result == 0){
				stack->pushLString(std::string(reinterpret_cast<char*>(output), plainTextLength));
			}
			else{
				stack->push<int>(result);
			}
			delete[] output;
			return 1;
		}
		return 0;
	}

	int RSAContext::signPKCS1(State & state, mbedtls_rsa_context * context){
		Stack * stack = state.stack;
		CTRDRBGContext * interfaceCTRDRBGContext = OBJECT_IFACE(CTRDRBGContext);
		mbedtls_ctr_drbg_context * drbg = interfaceCTRDRBGContext->get(1);

		if (drbg && stack->is<LUA_TNUMBER>(2) && stack->is<LUA_TNUMBER>(3) && stack->is<LUA_TSTRING>(4)){
			int mode = stack->to<int>(2);
			mbedtls_md_type_t  md_alg = static_cast<mbedtls_md_type_t>(stack->to<int>(3));
			const std::string hash = stack->toLString(4);

			const size_t outputLen = mbedtls_mpi_size(&context->N);
			unsigned char * sign = new unsigned char[outputLen];

			int result = mbedtls_rsa_pkcs1_sign(context, mbedtls_ctr_drbg_random, drbg, mode, md_alg,
				hash.length(), reinterpret_cast<const unsigned char *>(hash.c_str()), sign);
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

	int RSAContext::signRSASSAPKCS1v15(State & state, mbedtls_rsa_context * context){
		Stack * stack = state.stack;
		CTRDRBGContext * interfaceCTRDRBGContext = OBJECT_IFACE(CTRDRBGContext);
		mbedtls_ctr_drbg_context * drbg = interfaceCTRDRBGContext->get(1);

		if (drbg && stack->is<LUA_TNUMBER>(2) && stack->is<LUA_TNUMBER>(3) && stack->is<LUA_TSTRING>(4)){
			int mode = stack->to<int>(2);
			mbedtls_md_type_t  md_alg = static_cast<mbedtls_md_type_t >(stack->to<int>(3));
			const std::string hash = stack->toLString(4);

			const size_t outputLen = mbedtls_mpi_size(&context->N);
			unsigned char * sign = new unsigned char[outputLen];

			int result = mbedtls_rsa_rsassa_pkcs1_v15_sign(context, mbedtls_ctr_drbg_random, drbg, mode, md_alg,
				hash.length(), reinterpret_cast<const unsigned char *>(hash.c_str()), sign);
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
	int RSAContext::signRSASSAPSS(State & state, mbedtls_rsa_context * context){
		Stack * stack = state.stack;
		CTRDRBGContext * interfaceCTRDRBGContext = OBJECT_IFACE(CTRDRBGContext);
		mbedtls_ctr_drbg_context * drbg = interfaceCTRDRBGContext->get(1);

		if (drbg && stack->is<LUA_TNUMBER>(2) && stack->is<LUA_TNUMBER>(3) && stack->is<LUA_TSTRING>(4)){
			int mode = stack->to<int>(2);
			mbedtls_md_type_t  md_alg = static_cast<mbedtls_md_type_t>(stack->to<int>(3));
			const std::string hash = stack->toLString(4);

			const size_t outputLen = mbedtls_mpi_size(&context->N);
			unsigned char * sign = new unsigned char[outputLen];

			int result = mbedtls_rsa_rsassa_pss_sign(context, mbedtls_ctr_drbg_random, drbg, mode, md_alg,
				hash.length(), reinterpret_cast<const unsigned char *>(hash.c_str()), sign);
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
	int RSAContext::verifyPKCS1(State & state, mbedtls_rsa_context * context){
		Stack * stack = state.stack;
		CTRDRBGContext * interfaceCTRDRBGContext = OBJECT_IFACE(CTRDRBGContext);
		mbedtls_ctr_drbg_context * drbg = interfaceCTRDRBGContext->get(1);

		if (drbg && stack->is<LUA_TNUMBER>(2) && stack->is<LUA_TNUMBER>(3) && stack->is<LUA_TSTRING>(4) && stack->is<LUA_TSTRING>(5)){
			int mode = stack->to<int>(2);
			mbedtls_md_type_t  md_alg = static_cast<mbedtls_md_type_t>(stack->to<int>(3));
			const std::string hash = stack->toLString(4);
			const std::string sign = stack->toLString(5);

			stack->push<int>(mbedtls_rsa_pkcs1_verify(context, mbedtls_ctr_drbg_random, drbg, mode, md_alg,
				hash.length(), reinterpret_cast<const unsigned char *>(hash.c_str()), reinterpret_cast<const unsigned char *>(sign.c_str())));
			return 1;
		}
		return 0;
	}
	int RSAContext::verifyRSASSAPKCS1v15(State & state, mbedtls_rsa_context * context){
		Stack * stack = state.stack;
		CTRDRBGContext * interfaceCTRDRBGContext = OBJECT_IFACE(CTRDRBGContext);
		mbedtls_ctr_drbg_context * drbg = interfaceCTRDRBGContext->get(1);

		if (drbg && stack->is<LUA_TNUMBER>(2) && stack->is<LUA_TNUMBER>(3) && stack->is<LUA_TSTRING>(4) && stack->is<LUA_TSTRING>(5)){
			int mode = stack->to<int>(2);
			mbedtls_md_type_t  md_alg = static_cast<mbedtls_md_type_t>(stack->to<int>(3));
			const std::string hash = stack->toLString(4);
			const std::string sign = stack->toLString(5);

			stack->push<int>(mbedtls_rsa_rsassa_pkcs1_v15_verify(context, mbedtls_ctr_drbg_random, drbg, mode, md_alg,
				hash.length(), reinterpret_cast<const unsigned char *>(hash.c_str()), reinterpret_cast<const unsigned char *>(sign.c_str())));
			return 1;
		}
		return 0;
	}
	int RSAContext::verifyRSASSAPSS(State & state, mbedtls_rsa_context * context){
		Stack * stack = state.stack;
		CTRDRBGContext * interfaceCTRDRBGContext = OBJECT_IFACE(CTRDRBGContext);
		mbedtls_ctr_drbg_context * drbg = interfaceCTRDRBGContext->get(1);

		if (drbg && stack->is<LUA_TNUMBER>(2) && stack->is<LUA_TNUMBER>(3) && stack->is<LUA_TSTRING>(4) && stack->is<LUA_TSTRING>(5)){
			int mode = stack->to<int>(2);
			mbedtls_md_type_t  md_alg = static_cast<mbedtls_md_type_t>(stack->to<int>(3));
			const std::string hash = stack->toLString(4);
			const std::string sign = stack->toLString(5);

			stack->push<int>(mbedtls_rsa_rsassa_pss_verify(context, mbedtls_ctr_drbg_random, drbg, mode, md_alg,
				hash.length(), reinterpret_cast<const unsigned char *>(hash.c_str()), reinterpret_cast<const unsigned char *>(sign.c_str())));
			return 1;
		}
		return 0;
	}
	int RSAContext::verifyRSASSAPSSext(State & state, mbedtls_rsa_context * context){
		Stack * stack = state.stack;
		CTRDRBGContext * interfaceCTRDRBGContext = OBJECT_IFACE(CTRDRBGContext);
		mbedtls_ctr_drbg_context * drbg = interfaceCTRDRBGContext->get(1);

		if (drbg && stack->is<LUA_TNUMBER>(2) && stack->is<LUA_TNUMBER>(3) && stack->is<LUA_TSTRING>(4) && stack->is<LUA_TNUMBER>(5) && stack->is<LUA_TNUMBER>(6) && stack->is<LUA_TSTRING>(7)){
			int mode = stack->to<int>(2);
			mbedtls_md_type_t md_alg = static_cast<mbedtls_md_type_t>(stack->to<int>(3));
			const std::string hash = stack->toLString(4);
			mbedtls_md_type_t mgf1_hash_id = static_cast<mbedtls_md_type_t>(stack->to<int>(5));
			int expected_salt_len = stack->to<int>(6);
			const std::string sign = stack->toLString(7);

			stack->push<int>(mbedtls_rsa_rsassa_pss_verify_ext(context, mbedtls_ctr_drbg_random, drbg, mode, md_alg,
				hash.length(), reinterpret_cast<const unsigned char *>(hash.c_str()),
				mgf1_hash_id, expected_salt_len,
				reinterpret_cast<const unsigned char *>(sign.c_str())));
			return 1;
		}
		return 0;
	}
	
	int RSAContext::getLen(State & state, mbedtls_rsa_context * context){
		Stack * stack = state.stack;
		stack->push<int>(context->len);
		return 1;
	}
	int RSAContext::setLen(State & state, mbedtls_rsa_context * context){
		Stack * stack = state.stack;
		context->len = stack->to<int>(1);
		return 0;
	}

	int RSAContext::getN(State & state, mbedtls_rsa_context * context){
		PUSH_MPI(N);
	}
	int RSAContext::setN(State & state, mbedtls_rsa_context * context){
		READ_MPI(N);
	}
	int RSAContext::getE(State & state, mbedtls_rsa_context * context){
		PUSH_MPI(E);
	}
	int RSAContext::setE(State & state, mbedtls_rsa_context * context){
		READ_MPI(E);
	}

	int RSAContext::getD(State & state, mbedtls_rsa_context * context){
		PUSH_MPI(D);
	}
	int RSAContext::setD(State & state, mbedtls_rsa_context * context){
		READ_MPI(D);
	}
	int RSAContext::getP(State & state, mbedtls_rsa_context * context){
		PUSH_MPI(P);
	}
	int RSAContext::setP(State & state, mbedtls_rsa_context * context){
		READ_MPI(P);
	}
	int RSAContext::getQ(State & state, mbedtls_rsa_context * context){
		PUSH_MPI(Q);
	}
	int RSAContext::setQ(State & state, mbedtls_rsa_context * context){
		READ_MPI(Q);
	}
	int RSAContext::getDP(State & state, mbedtls_rsa_context * context){
		PUSH_MPI(DP);
	}
	int RSAContext::setDP(State & state, mbedtls_rsa_context * context){
		READ_MPI(DP);
	}
	int RSAContext::getDQ(State & state, mbedtls_rsa_context * context){
		PUSH_MPI(DQ);
	}
	int RSAContext::setDQ(State & state, mbedtls_rsa_context * context){
		READ_MPI(DQ);
	}
	int RSAContext::getQP(State & state, mbedtls_rsa_context * context){
		PUSH_MPI(QP);
	}
	int RSAContext::setQP(State & state, mbedtls_rsa_context * context){
		READ_MPI(QP);
	}

	int RSAContext::getRN(State & state, mbedtls_rsa_context * context){
		PUSH_MPI(RN);
	}
	int RSAContext::setRN(State & state, mbedtls_rsa_context * context){
		READ_MPI(RN);
	}
	int RSAContext::getRP(State & state, mbedtls_rsa_context * context){
		PUSH_MPI(RP);
	}
	int RSAContext::setRP(State & state, mbedtls_rsa_context * context){
		READ_MPI(RP);
	}
	int RSAContext::getRQ(State & state, mbedtls_rsa_context * context){
		PUSH_MPI(RQ);
	}
	int RSAContext::setRQ(State & state, mbedtls_rsa_context * context){
		READ_MPI(RQ);
	}

	int RSAContext::getVi(State & state, mbedtls_rsa_context * context){
		PUSH_MPI(Vi);
	}
	int RSAContext::setVi(State & state, mbedtls_rsa_context * context){
		READ_MPI(Vi);
	}
	int RSAContext::getVf(State & state, mbedtls_rsa_context * context){
		PUSH_MPI(Vf);
	}
	int RSAContext::setVf(State & state, mbedtls_rsa_context * context){
		READ_MPI(Vf);
	}

	int RSAContext::getPaddingOnly(State & state, mbedtls_rsa_context * context){
		Stack * stack = state.stack;
		stack->push<int>(context->padding);
		return 1;
	}
	int RSAContext::setPaddingOnly(State & state, mbedtls_rsa_context * context){
		Stack * stack = state.stack;
		context->padding = stack->to<int>(1);
		return 0;
	}

	int RSAContext::getHashID(State & state, mbedtls_rsa_context * context){
		Stack * stack = state.stack;
		stack->push<int>(context->hash_id);
		return 1;
	}
	int RSAContext::setHashID(State & state, mbedtls_rsa_context * context){
		Stack * stack = state.stack;
		context->hash_id = stack->to<int>(1);
		return 0;
	}

	int RSASelfTest(State & state){
		Stack * stack = state.stack;
		stack->push<int>(mbedtls_rsa_self_test(stack->to<int>(1)));
		return 1;
	}

	void initRSAContext(State * state, Module & module){
		INIT_OBJECT(RSAContext);
		module["RSASelfTest"] = RSASelfTest;
	}
};
