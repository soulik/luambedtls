#include "objects/x509writeCert.hpp"
#include "objects/PKContext.hpp"
#include "objects/MPI.hpp"
#include "objects/CTRDRBGContext.hpp"

namespace luambedtls {
	mbedtls_x509write_cert * x509writeCert::constructor(State & state, bool & managed){
		mbedtls_x509write_cert * object = new mbedtls_x509write_cert;
		mbedtls_x509write_crt_init(object);
		return object;
	}

	void x509writeCert::destructor(State & state, mbedtls_x509write_cert * object){
		mbedtls_x509write_crt_free(object);
		delete object;
	}
	
	int x509writeCert::setVersion(State & state, mbedtls_x509write_cert * object){
		Stack * stack = state.stack;
		mbedtls_x509write_crt_set_version(object, stack->to<int>(1));
		return 0;
	}
	int x509writeCert::setMDAlg(State & state, mbedtls_x509write_cert * object){
		Stack * stack = state.stack;
		mbedtls_x509write_crt_set_md_alg(object, static_cast<mbedtls_md_type_t>(stack->to<int>(1)));
		return 0;
	}
	int x509writeCert::setSubjectKey(State & state, mbedtls_x509write_cert * object){
		Stack * stack = state.stack;
		PKContext * interfacePK = OBJECT_IFACE(PKContext);
		mbedtls_pk_context * key = interfacePK->get(1);
		if (key){
			mbedtls_x509write_crt_set_subject_key(object, key);
		}
		return 0;
	}
	int x509writeCert::setIssuerKey(State & state, mbedtls_x509write_cert * object){
		Stack * stack = state.stack;
		PKContext * interfacePK = OBJECT_IFACE(PKContext);
		mbedtls_pk_context * key = interfacePK->get(1);
		if (key){
			mbedtls_x509write_crt_set_issuer_key(object, key);
		}
		return 0;
	}
	int x509writeCert::setSubjectName(State & state, mbedtls_x509write_cert * object){
		Stack * stack = state.stack;
		if (stack->is<LUA_TSTRING>(1)){
			const std::string name = stack->to<const std::string>(1);
			mbedtls_x509write_crt_set_subject_name(object, name.c_str());
		}
		return 0;
	}
	int x509writeCert::setIssuerName(State & state, mbedtls_x509write_cert * object){
		Stack * stack = state.stack;
		if (stack->is<LUA_TSTRING>(1)){
			const std::string name = stack->to<const std::string>(1);
			mbedtls_x509write_crt_set_issuer_name(object, name.c_str());
		}
		return 0;
	}
	int x509writeCert::setSerial(State & state, mbedtls_x509write_cert * object){
		Stack * stack = state.stack;
		MPI * interfaceMPI = OBJECT_IFACE(MPI);
		mbedtls_mpi * serial = interfaceMPI->get(1);
		if (serial){
			mbedtls_x509write_crt_set_serial(object, serial);
		}
		return 0;
	}
	int x509writeCert::setValidity(State & state, mbedtls_x509write_cert * object){
		Stack * stack = state.stack;
		if (stack->is<LUA_TSTRING>(1) && stack->is<LUA_TSTRING>(2)){
			const std::string notBefore = stack->to<const std::string>(1);
			const std::string notAfter = stack->to<const std::string>(2);
			stack->push<int>(mbedtls_x509write_crt_set_validity(object, notBefore.c_str(), notAfter.c_str()));
			return 1;
		}
		return 0;
	}
	int x509writeCert::setExtensions(State & state, mbedtls_x509write_cert * object){
		Stack * stack = state.stack;
		if (stack->is<LUA_TSTRING>(1) && stack->is<LUA_TSTRING>(2) && stack->is<LUA_TNUMBER>(3)){
			const std::string oid = stack->toLString(1);
			const std::string value = stack->toLString(2);
			int critical = stack->to<int>(3);

			stack->push<int>(mbedtls_x509write_crt_set_extension(object, oid.c_str(), oid.length(), critical, reinterpret_cast<const unsigned char *>(value.c_str()), value.length()));
			return 1;
		}
		return 0;
	}
	int x509writeCert::setBasicConstraints(State & state, mbedtls_x509write_cert * object){
		Stack * stack = state.stack;
		if (stack->is<LUA_TNUMBER>(1) || (stack->is<LUA_TBOOLEAN>(1)) && stack->is<LUA_TNUMBER>(2)){
			stack->push<int>(mbedtls_x509write_crt_set_basic_constraints(object, stack->to<int>(1), stack->to<int>(2)));
			return 1;
		}
		return 0;
	}
	int x509writeCert::setSubjectKeyIdentifier(State & state, mbedtls_x509write_cert * object){
		Stack * stack = state.stack;
		stack->push<int>(mbedtls_x509write_crt_set_subject_key_identifier(object));
		return 1;
	}
	int x509writeCert::setAuthorityKeyIdentifier(State & state, mbedtls_x509write_cert * object){
		Stack * stack = state.stack;
		stack->push<int>(mbedtls_x509write_crt_set_authority_key_identifier(object));
		return 1;
	}
	int x509writeCert::setKeyUsage(State & state, mbedtls_x509write_cert * object){
		Stack * stack = state.stack;
		if (stack->is<LUA_TNUMBER>(1)){
			stack->push<int>(mbedtls_x509write_crt_set_key_usage(object, stack->to<int>(1)));
			return 1;
		}
		return 0;
	}
	int x509writeCert::setNSCertType(State & state, mbedtls_x509write_cert * object){
		Stack * stack = state.stack;
		if (stack->is<LUA_TNUMBER>(1)){
			stack->push<int>(mbedtls_x509write_crt_set_ns_cert_type(object, stack->to<int>(1)));
			return 1;
		}
		return 0;
	}

	int x509writeCert::writePEM(State & state, mbedtls_x509write_cert * object){
		Stack * stack = state.stack;
		CTRDRBGContext * interfaceCTRDRBGContext = OBJECT_IFACE(CTRDRBGContext);
		mbedtls_ctr_drbg_context * drbg = interfaceCTRDRBGContext->get(2);
		if (drbg && stack->is<LUA_TNUMBER>(1)){
			const size_t outputLen = stack->to<int>(1);
			unsigned char * output = new unsigned char[outputLen];

			int result = mbedtls_x509write_crt_pem(object, output, outputLen, mbedtls_ctr_drbg_random, drbg);
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


	int x509writeCert::writeDER(State & state, mbedtls_x509write_cert * object){
		Stack * stack = state.stack;
		CTRDRBGContext * interfaceCTRDRBGContext = OBJECT_IFACE(CTRDRBGContext);
		mbedtls_ctr_drbg_context * drbg = interfaceCTRDRBGContext->get(2);
		if (drbg && stack->is<LUA_TNUMBER>(1)){
			const size_t outputLen = stack->to<int>(1);
			unsigned char * output = new unsigned char[outputLen];

			int result = mbedtls_x509write_crt_der(object, output, outputLen, mbedtls_ctr_drbg_random, drbg);
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

	void initx509writeCert(State * state, Module & module){
		INIT_OBJECT(x509writeCert);
	}
};
