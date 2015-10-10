#include "objects/ECSDAContext.hpp"
#include "objects/ECPKeyPair.hpp"
#include "objects/ECPGroup.hpp"
#include "objects/ECPPoint.hpp"
#include "objects/MPI.hpp"
#include "objects/CTRDRBGContext.hpp"

namespace luambedtls {
	ecsda_wrapper * ECSDAContext::constructor(State & state, bool & managed){
		Stack * stack = state.stack;

		ecsda_wrapper * context = new ecsda_wrapper;
		context->context = new mbedtls_ecdsa_context;
		mbedtls_ecdsa_init(context->context);
		if (stack->getTop() > 0){
			ECPKeyPair * interfaceECPKeyPair = OBJECT_IFACE(ECPKeyPair);
			mbedtls_ecp_keypair * keyPair = interfaceECPKeyPair->get(1);
			if (keyPair){
				int result = mbedtls_ecdsa_from_keypair(context->context, keyPair);
				if (result == 0){
					return context;
				}
				else{
					delete context->context; delete context;
					char buffer[1024];
					mbedtls_strerror(result, buffer, 1024);
					state.error("%s", buffer);
					return nullptr;
				}
			}
		}
		return context;
	}

	void ECSDAContext::destructor(State & state, ecsda_wrapper * context){
		mbedtls_ecdsa_free(context->context);
		delete context->context;
		delete context;
	}

	int ECSDAContext::sign(State & state, ecsda_wrapper * context){
		Stack * stack = state.stack;
		CTRDRBGContext * interfaceCTRDRBG = OBJECT_IFACE(CTRDRBGContext);
		ECPGroup * interfaceECPGroup = OBJECT_IFACE(ECPGroup);
		MPI * interfaceMPI = OBJECT_IFACE(MPI);

		mbedtls_ecp_group * group = interfaceECPGroup->get(1);
		mbedtls_mpi * d = interfaceMPI->get(2);
		mbedtls_ctr_drbg_context * ctrdrbg = interfaceCTRDRBG->get(4);
		if (group && d && ctrdrbg && stack->is<LUA_TSTRING>(3)){
			mbedtls_mpi * r = new mbedtls_mpi; mbedtls_mpi_init(r);
			mbedtls_mpi * s = new mbedtls_mpi; mbedtls_mpi_init(s);
			const std::string hash = stack->toLString(3);
			int result = mbedtls_ecdsa_sign(group, r, s, d, reinterpret_cast<const unsigned char*>(hash.c_str()), hash.length(), mbedtls_ctr_drbg_random, ctrdrbg);
			if (result == 0){
				interfaceMPI->push(r, true);
				interfaceMPI->push(s, true);
				return 2;
			}
			else{
				stack->push<int>(result);
				mbedtls_mpi_free(r);
				mbedtls_mpi_free(s);
				delete r;
				delete s;
				return 1;
			}
		}
		return 0;
	}
	int ECSDAContext::signDet(State & state, ecsda_wrapper * context){
		Stack * stack = state.stack;
		ECPGroup * interfaceECPGroup = OBJECT_IFACE(ECPGroup);
		MPI * interfaceMPI = OBJECT_IFACE(MPI);

		mbedtls_ecp_group * group = interfaceECPGroup->get(1);
		mbedtls_mpi * d = interfaceMPI->get(2);
		if (group && d && stack->is<LUA_TSTRING>(3) && stack->is<LUA_TSTRING>(4)){
			mbedtls_mpi * r = new mbedtls_mpi; mbedtls_mpi_init(r);
			mbedtls_mpi * s = new mbedtls_mpi; mbedtls_mpi_init(s);
			const std::string hash = stack->toLString(3);
			int result = mbedtls_ecdsa_sign_det(group, r, s, d, reinterpret_cast<const unsigned char*>(hash.c_str()), hash.length(), static_cast<mbedtls_md_type_t>(stack->to<int>(4)));
			if (result == 0){
				interfaceMPI->push(r, true);
				interfaceMPI->push(s, true);
				return 2;
			}
			else{
				stack->push<int>(result);
				mbedtls_mpi_free(r);
				mbedtls_mpi_free(s);
				delete r;
				delete s;
				return 1;
			}
		}
		return 0;
	}
	int ECSDAContext::verify(State & state, ecsda_wrapper * context){
		Stack * stack = state.stack;
		ECPGroup * interfaceECPGroup = OBJECT_IFACE(ECPGroup);
		ECPPoint * interfaceECPPoint = OBJECT_IFACE(ECPPoint);
		MPI * interfaceMPI = OBJECT_IFACE(MPI);

		mbedtls_ecp_group * group = interfaceECPGroup->get(1);
		mbedtls_ecp_point * Q = interfaceECPPoint->get(3);
		mbedtls_mpi * r = interfaceMPI->get(4);
		mbedtls_mpi * s = interfaceMPI->get(5);

		if (group && Q && r && s && stack->is<LUA_TSTRING>(2)){
			const std::string hash = stack->toLString(2);
			stack->push<int>(mbedtls_ecdsa_verify(group, reinterpret_cast<const unsigned char*>(hash.c_str()), hash.length(), Q, r, s));
			return 1;
		}

		return 0;
	}
	int ECSDAContext::writeSignature(State & state, ecsda_wrapper * context){
		Stack * stack = state.stack;
		CTRDRBGContext * interfaceCTRDRBG = OBJECT_IFACE(CTRDRBGContext);
		mbedtls_ctr_drbg_context * ctrdrbg = interfaceCTRDRBG->get(3);

		if (ctrdrbg && stack->is<LUA_TNUMBER>(1) && stack->is<LUA_TSTRING>(2)){
			mbedtls_md_type_t  md_alg = static_cast<mbedtls_md_type_t>(stack->to<int>(1));
			const std::string hash = stack->toLString(2);

			size_t outputLen = (context->context->grp.nbits * 8) * 2 + 9;
			unsigned char * sign = new unsigned char[outputLen];

			int result = mbedtls_ecdsa_write_signature(context->context, md_alg,
				reinterpret_cast<const unsigned char *>(hash.c_str()), hash.length(),
				sign, &outputLen,
				mbedtls_ctr_drbg_random, ctrdrbg);
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
	int ECSDAContext::writeSignatureDet(State & state, ecsda_wrapper * context){
		Stack * stack = state.stack;

		if (stack->is<LUA_TSTRING>(1) && stack->is<LUA_TNUMBER>(2)){
			const std::string hash = stack->toLString(1);
			mbedtls_md_type_t  md_alg = static_cast<mbedtls_md_type_t>(stack->to<int>(2));

			size_t outputLen = (context->context->grp.nbits * 8) * 2 + 9;
			unsigned char * sign = new unsigned char[outputLen];

			int result = mbedtls_ecdsa_write_signature_det(context->context,
				reinterpret_cast<const unsigned char *>(hash.c_str()), hash.length(),
				sign, &outputLen,
				md_alg);
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
	int ECSDAContext::readSignature(State & state, ecsda_wrapper * context){
		Stack * stack = state.stack;
		if (stack->is<LUA_TSTRING>(1) && stack->is<LUA_TSTRING>(2)){
			const std::string hash = stack->toLString(1);
			const std::string sig = stack->toLString(2);
			stack->push<int>(mbedtls_ecdsa_read_signature(context->context,
				reinterpret_cast<const unsigned char *>(hash.c_str()), hash.length(),
				reinterpret_cast<const unsigned char *>(sig.c_str()), sig.length()));
			return 1;
		}
		return 0;
	}
	int ECSDAContext::genKey(State & state, ecsda_wrapper * context){
		Stack * stack = state.stack;
		CTRDRBGContext * interfaceCTRDRBG = OBJECT_IFACE(CTRDRBGContext);
		mbedtls_ctr_drbg_context * ctrdrbg = interfaceCTRDRBG->get(2);
		if (ctrdrbg && stack->is<LUA_TNUMBER>(1)){
			stack->push<int>(mbedtls_ecdsa_genkey(context->context, static_cast<mbedtls_ecp_group_id>(stack->to<int>(1)), mbedtls_ctr_drbg_random, ctrdrbg));
			return 1;
		}
		return 0;
	}
	int ECSDAContext::fromKeypair(State & state, ecsda_wrapper * context){
		Stack * stack = state.stack;
		ECPKeyPair * interfaceECPKeyPair = OBJECT_IFACE(ECPKeyPair);
		mbedtls_ecp_keypair * keyPair = interfaceECPKeyPair->get(1);
		if (keyPair){
			stack->push<int>(mbedtls_ecdsa_from_keypair(context->context, keyPair));
			return 1;
		}
		return 0;
	}

	int ECSDAContext::getKeypair(State & state, ecsda_wrapper * context){
		Stack * stack = state.stack;
		ECPKeyPair * interfaceECPKeyPair = OBJECT_IFACE(ECPKeyPair);
		interfaceECPKeyPair->push(context->context);
		return 1;
	}

	void initECSDAContext(State * state, Module & module){
		INIT_OBJECT(ECSDAContext);
	}
};
