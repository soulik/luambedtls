#include "objects/ECDHContext.hpp"
#include "objects/ECPKeyPair.hpp"
#include "objects/ECPGroup.hpp"
#include "objects/ECPPoint.hpp"
#include "objects/MPI.hpp"
#include "objects/CTRDRBGContext.hpp"

namespace luambedtls {
	mbedtls_ecdh_context * ECDHContext::constructor(State & state, bool & managed){
		mbedtls_ecdh_context * context = new mbedtls_ecdh_context;
		mbedtls_ecdh_init(context);
		return context;
	}

	void ECDHContext::destructor(State & state, mbedtls_ecdh_context * context){
		mbedtls_ecdh_free(context);
		delete context;
	}

	int ECDHContext::genPublic(State & state, mbedtls_ecdh_context * context){
		Stack * stack = state.stack;
		CTRDRBGContext * interfaceCTRDRBG = OBJECT_IFACE(CTRDRBGContext);
		ECPGroup * interfaceECPGroup = OBJECT_IFACE(ECPGroup);
		ECPPoint * interfaceECPPoint = OBJECT_IFACE(ECPPoint);
		MPI * interfaceMPI = OBJECT_IFACE(MPI);
		
		mbedtls_ecp_group * group = interfaceECPGroup->get(1);
		mbedtls_ctr_drbg_context * ctrdrbg = interfaceCTRDRBG->get(2);
		if (group && ctrdrbg){
			mbedtls_mpi * d = new mbedtls_mpi; mbedtls_mpi_init(d);
			mbedtls_ecp_point * Q = new mbedtls_ecp_point; mbedtls_ecp_point_init(Q);

			int result = mbedtls_ecdh_gen_public(group, d, Q, mbedtls_ctr_drbg_random, ctrdrbg);
			if (result == 0){
				interfaceMPI->push(d, true);
				interfaceECPPoint->push(Q, true);
				return 2;
			}
			else{
				stack->push<int>(result);
				mbedtls_mpi_free(d);
				mbedtls_ecp_point_free(Q);
				delete d;
				delete Q;
				return 1;
			}
		}
		return 0;
	}
	int ECDHContext::computeShared(State & state, mbedtls_ecdh_context * context){
		Stack * stack = state.stack;
		CTRDRBGContext * interfaceCTRDRBG = OBJECT_IFACE(CTRDRBGContext);
		ECPGroup * interfaceECPGroup = OBJECT_IFACE(ECPGroup);
		ECPPoint * interfaceECPPoint = OBJECT_IFACE(ECPPoint);
		MPI * interfaceMPI = OBJECT_IFACE(MPI);

		mbedtls_ecp_group * group = interfaceECPGroup->get(1);
		mbedtls_ecp_point * Q = interfaceECPPoint->get(2);
		mbedtls_mpi * d = interfaceMPI->get(3);
		mbedtls_ctr_drbg_context * ctrdrbg = interfaceCTRDRBG->get(4);
		if (group && Q && d && ctrdrbg){
			mbedtls_mpi * z = new mbedtls_mpi; mbedtls_mpi_init(z);
			int result = mbedtls_ecdh_compute_shared(group, z, Q, d, mbedtls_ctr_drbg_random, ctrdrbg);
			if (result == 0){
				interfaceMPI->push(z, true);
				return 1;
			}
			else{
				stack->push<int>(result);
				mbedtls_mpi_free(z);
				delete z;
				return 1;
			}
		}
		return 0;
	}
	int ECDHContext::makeParams(State & state, mbedtls_ecdh_context * context){
		Stack * stack = state.stack;
		CTRDRBGContext * interfaceCTRDRBG = OBJECT_IFACE(CTRDRBGContext);
		mbedtls_ctr_drbg_context * ctrdrbg = interfaceCTRDRBG->get(2);
		if (stack->is<LUA_TNUMBER>(1) && ctrdrbg){
			const size_t bufferMaxLength = stack->to<int>(1);
			size_t bufferLength = 0;
			unsigned char * buffer = new unsigned char[bufferMaxLength];

			int result = mbedtls_ecdh_make_params(context, &bufferLength, buffer, bufferMaxLength, mbedtls_ctr_drbg_random, ctrdrbg);
			if (result == 0){
				stack->pushLString(std::string(reinterpret_cast<char *>(buffer), bufferLength));
			}
			else{
				stack->push<int>(result);
			}
			delete[] buffer;
			return 1;
		}
		return 0;
	}
	int ECDHContext::readParams(State & state, mbedtls_ecdh_context * context){
		Stack * stack = state.stack;
		if (stack->is<LUA_TSTRING>(1)){
			const std::string bufferStr = stack->toLString(1);
			const unsigned char * buffer = reinterpret_cast<const unsigned char *>(bufferStr.c_str());
			const unsigned char * bufferEnd = reinterpret_cast<const unsigned char *>(bufferStr.c_str()) + bufferStr.length();
			int result = mbedtls_ecdh_read_params(context, &buffer, bufferEnd);
			if (result == 0){
				size_t newLength = (bufferEnd - buffer);
				stack->pushLString(std::string(reinterpret_cast<const char *>(buffer), newLength));
			}
			else{
				stack->push<int>(result);
			}
			return 1;
		}
		return 0;
	}
	int ECDHContext::getParams(State & state, mbedtls_ecdh_context * context){
		Stack * stack = state.stack;
		ECPKeyPair * interfaceECPKeyPair = OBJECT_IFACE(ECPKeyPair);
		mbedtls_ecp_keypair * keyPair = interfaceECPKeyPair->get(1);
		if (keyPair && stack->is<LUA_TNUMBER>(2)){
			stack->push<int>(mbedtls_ecdh_get_params(context, keyPair, static_cast<mbedtls_ecdh_side>(stack->to<int>(1))));
			return 1;
		}
		return 0;
	}
	int ECDHContext::makePublic(State & state, mbedtls_ecdh_context * context){
		Stack * stack = state.stack;
		CTRDRBGContext * interfaceCTRDRBG = OBJECT_IFACE(CTRDRBGContext);
		mbedtls_ctr_drbg_context * ctrdrbg = interfaceCTRDRBG->get(2);
		if (stack->is<LUA_TNUMBER>(1) && ctrdrbg){
			const size_t bufferMaxLength = stack->to<int>(1);
			size_t bufferLength = 0;
			unsigned char * buffer = new unsigned char[bufferMaxLength];

			int result = mbedtls_ecdh_make_public(context, &bufferLength, buffer, bufferMaxLength, mbedtls_ctr_drbg_random, ctrdrbg);
			if (result == 0){
				stack->pushLString(std::string(reinterpret_cast<char *>(buffer), bufferLength));
			}
			else{
				stack->push<int>(result);
			}
			delete[] buffer;
			return 1;
		}
		return 0;
	}
	int ECDHContext::readPublic(State & state, mbedtls_ecdh_context * context){
		Stack * stack = state.stack;
		if (stack->is<LUA_TSTRING>(1)){
			const std::string bufferStr = stack->toLString(1);
			stack->push<int>(mbedtls_ecdh_read_public(context, reinterpret_cast<const unsigned char *>(bufferStr.c_str()), bufferStr.length()));
			return 1;
		}
		return 0;
	}
	int ECDHContext::calcSecret(State & state, mbedtls_ecdh_context * context){
		Stack * stack = state.stack;
		CTRDRBGContext * interfaceCTRDRBG = OBJECT_IFACE(CTRDRBGContext);
		mbedtls_ctr_drbg_context * ctrdrbg = interfaceCTRDRBG->get(2);
		if (stack->is<LUA_TNUMBER>(1) && ctrdrbg){
			const size_t bufferMaxLength = stack->to<int>(1);
			size_t bufferLength = 0;
			unsigned char * buffer = new unsigned char[bufferMaxLength];

			int result = mbedtls_ecdh_calc_secret(context, &bufferLength, buffer, bufferMaxLength, mbedtls_ctr_drbg_random, ctrdrbg);
			if (result == 0){
				stack->pushLString(std::string(reinterpret_cast<char *>(buffer), bufferLength));
			}
			else{
				stack->push<int>(result);
			}
			delete[] buffer;
			return 1;
		}
		return 0;
	}

	int ECDHContext::getGroup(State & state, mbedtls_ecdh_context * context){
		Stack * stack = state.stack;
		ECPGroup * interfaceECPGroup = OBJECT_IFACE(ECPGroup);
		interfaceECPGroup->push(&context->grp);
		return 1;
	}
	int ECDHContext::getd(State & state, mbedtls_ecdh_context * context){
		Stack * stack = state.stack;
		MPI * interfaceMPI = OBJECT_IFACE(MPI);
		interfaceMPI->push(&context->d);
		return 1;
	}
	int ECDHContext::getQ(State & state, mbedtls_ecdh_context * context){
		Stack * stack = state.stack;
		ECPPoint * interfaceECPPoint = OBJECT_IFACE(ECPPoint);
		interfaceECPPoint->push(&context->Q);
		return 1;
	}
	int ECDHContext::getQp(State & state, mbedtls_ecdh_context * context){
		Stack * stack = state.stack;
		ECPPoint * interfaceECPPoint = OBJECT_IFACE(ECPPoint);
		interfaceECPPoint->push(&context->Qp);
		return 1;
	}
	int ECDHContext::getz(State & state, mbedtls_ecdh_context * context){
		Stack * stack = state.stack;
		MPI * interfaceMPI = OBJECT_IFACE(MPI);
		interfaceMPI->push(&context->z);
		return 1;
	}
	int ECDHContext::getPointFormat(State & state, mbedtls_ecdh_context * context){
		Stack * stack = state.stack;
		stack->push<int>(context->point_format);
		return 1;
	}
	int ECDHContext::getVi(State & state, mbedtls_ecdh_context * context){
		Stack * stack = state.stack;
		ECPPoint * interfaceECPPoint = OBJECT_IFACE(ECPPoint);
		interfaceECPPoint->push(&context->Vi);
		return 1;
	}
	int ECDHContext::getVf(State & state, mbedtls_ecdh_context * context){
		Stack * stack = state.stack;
		ECPPoint * interfaceECPPoint = OBJECT_IFACE(ECPPoint);
		interfaceECPPoint->push(&context->Vf);
		return 1;
	}

	int ECDHContext::setGroup(State & state, mbedtls_ecdh_context * context){
		Stack * stack = state.stack;
		ECPGroup * interfaceECPGroup = OBJECT_IFACE(ECPGroup);
		mbedtls_ecp_group * group = interfaceECPGroup->get(1);
		if (group){
			mbedtls_ecp_group_copy(&context->grp, group);
		}
		return 0;
	}
	int ECDHContext::setd(State & state, mbedtls_ecdh_context * context){
		Stack * stack = state.stack;
		MPI * interfaceMPI = OBJECT_IFACE(MPI);
		mbedtls_mpi * d = interfaceMPI->get(1);
		if (d){
			mbedtls_mpi_copy(&context->d, d);
		}
		return 0;
	}
	int ECDHContext::setQ(State & state, mbedtls_ecdh_context * context){
		Stack * stack = state.stack;
		ECPPoint * interfaceECPPoint = OBJECT_IFACE(ECPPoint);
		mbedtls_ecp_point * Q = interfaceECPPoint->get(1);
		if (Q){
			mbedtls_ecp_copy(&context->Q, Q);
		}
		return 0;
	}
	int ECDHContext::setQp(State & state, mbedtls_ecdh_context * context){
		Stack * stack = state.stack;
		ECPPoint * interfaceECPPoint = OBJECT_IFACE(ECPPoint);
		mbedtls_ecp_point * Qp = interfaceECPPoint->get(1);
		if (Qp){
			mbedtls_ecp_copy(&context->Qp, Qp);
		}
		return 0;
	}
	int ECDHContext::setz(State & state, mbedtls_ecdh_context * context){
		Stack * stack = state.stack;
		MPI * interfaceMPI = OBJECT_IFACE(MPI);
		mbedtls_mpi * z = interfaceMPI->get(1);
		if (z){
			mbedtls_mpi_copy(&context->z, z);
		}
		return 0;
	}
	int ECDHContext::setPointFormat(State & state, mbedtls_ecdh_context * context){
		Stack * stack = state.stack;
		if (stack->is<LUA_TNUMBER>(1)){
			context->point_format = stack->to<int>(1);
		}
		return 0;
	}
	int ECDHContext::setVi(State & state, mbedtls_ecdh_context * context){
		Stack * stack = state.stack;
		ECPPoint * interfaceECPPoint = OBJECT_IFACE(ECPPoint);
		mbedtls_ecp_point * Vi = interfaceECPPoint->get(1);
		if (Vi){
			mbedtls_ecp_copy(&context->Vi, Vi);
		}
		return 0;
	}
	int ECDHContext::setVf(State & state, mbedtls_ecdh_context * context){
		Stack * stack = state.stack;
		ECPPoint * interfaceECPPoint = OBJECT_IFACE(ECPPoint);
		mbedtls_ecp_point * Vf = interfaceECPPoint->get(1);
		if (Vf){
			mbedtls_ecp_copy(&context->Vf, Vf);
		}
		return 0;
	}

	void initECDHContext(State * state, Module & module){
		INIT_OBJECT(ECDHContext);
	}
};
