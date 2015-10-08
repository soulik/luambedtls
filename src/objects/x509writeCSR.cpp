#include "objects/x509writeCSR.hpp"
#include "objects/PKContext.hpp"
#include "objects/ASN1buf.hpp"
#include "objects/ASN1named.hpp"
#include "objects/CTRDRBGContext.hpp"

namespace luambedtls {
	mbedtls_x509write_csr * x509writeCSR::constructor(State & state, bool & managed){
		mbedtls_x509write_csr * request = new mbedtls_x509write_csr;
		mbedtls_x509write_csr_init(request);
		return request;
	}

	void x509writeCSR::destructor(State & state, mbedtls_x509write_csr * request){
		mbedtls_x509write_csr_free(request);
		delete request;
	}

	int x509writeCSR::setKey(State & state, mbedtls_x509write_csr * request){
		Stack * stack = state.stack;
		PKContext * interfacePK = OBJECT_IFACE(PKContext);
		mbedtls_pk_context * key = interfacePK->get(1);
		if (key){
			mbedtls_x509write_csr_set_key(request, key);
		}
		return 0;
	}

	int x509writeCSR::setSubject(State & state, mbedtls_x509write_csr * request){
		Stack * stack = state.stack;
		if (stack->is<LUA_TSTRING>(1)){
			const std::string subject = stack->to<const std::string>(1);
			mbedtls_x509write_csr_set_subject_name(request, subject.c_str());
		}
		return 0;
	}
	int x509writeCSR::setMDAlg(State & state, mbedtls_x509write_csr * request){
		Stack * stack = state.stack;
		mbedtls_x509write_csr_set_md_alg(request, static_cast<mbedtls_md_type_t>(stack->to<int>(1)));
		return 0;
	}
	int x509writeCSR::setExtensions(State & state, mbedtls_x509write_csr * request){
		Stack * stack = state.stack;
		if (stack->is<LUA_TSTRING>(1) && stack->is<LUA_TSTRING>(2)){
			const std::string oid = stack->toLString(1);
			const std::string value = stack->toLString(2);
			stack->push<int>(mbedtls_x509write_csr_set_extension(request, oid.c_str(), oid.length(), reinterpret_cast<const unsigned char *>(value.c_str()), value.length()));
			return 1;
		}
		return 0;
	}
	int x509writeCSR::setNSCertType(State & state, mbedtls_x509write_csr * request){
		Stack * stack = state.stack;
		if (stack->is<LUA_TNUMBER>(1)){
			mbedtls_x509write_csr_set_ns_cert_type(request, stack->to<int>(1));
		}
		return 0;
	}

	int x509writeCSR::writePEM(State & state, mbedtls_x509write_csr * request){
		Stack * stack = state.stack;
		CTRDRBGContext * interfaceCTRDRBGContext = OBJECT_IFACE(CTRDRBGContext);
		mbedtls_ctr_drbg_context * drbg = interfaceCTRDRBGContext->get(2);
		if (drbg && stack->is<LUA_TNUMBER>(1)){
			const size_t outputLen = stack->to<int>(1);
			unsigned char * output = new unsigned char[outputLen];

			int result = mbedtls_x509write_csr_pem(request, output, outputLen, mbedtls_ctr_drbg_random, drbg);
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


	int x509writeCSR::writeDER(State & state, mbedtls_x509write_csr * request){
		Stack * stack = state.stack;
		CTRDRBGContext * interfaceCTRDRBGContext = OBJECT_IFACE(CTRDRBGContext);
		mbedtls_ctr_drbg_context * drbg = interfaceCTRDRBGContext->get(2);
		if (drbg && stack->is<LUA_TNUMBER>(1)){
			const size_t outputLen = stack->to<int>(1);
			unsigned char * output = new unsigned char[outputLen];

			int result = mbedtls_x509write_csr_der(request, output, outputLen, mbedtls_ctr_drbg_random, drbg);
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

	void initx509writeCSR(State * state, Module & module){
		INIT_OBJECT(x509writeCSR);
	}
};
