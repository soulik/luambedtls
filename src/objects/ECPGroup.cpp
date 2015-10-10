#include "objects/ECPGroup.hpp"
#include "objects/ECPPoint.hpp"
#include "objects/ECPKeyPair.hpp"
#include "objects/MPI.hpp"
#include "objects/CTRDRBGContext.hpp"

namespace luambedtls {
	mbedtls_ecp_group * ECPGroup::constructor(State & state, bool & managed){
		mbedtls_ecp_group * group = new mbedtls_ecp_group;
		mbedtls_ecp_group_init(group);
		return group;
	}

	void ECPGroup::destructor(State & state, mbedtls_ecp_group * group){
		mbedtls_ecp_group_free(group);
		delete group;
	}

	int ECPGroup::getGroupID(State & state, mbedtls_ecp_group * group){
		Stack * stack = state.stack;
		stack->push<int>(group->id);
		return 1;
	}
	int ECPGroup::getP(State & state, mbedtls_ecp_group * group){
		Stack * stack = state.stack;
		MPI * interfaceMPI = OBJECT_IFACE(MPI);
		interfaceMPI->push(&group->P);
		return 1;
	}
	int ECPGroup::getA(State & state, mbedtls_ecp_group * group){
		Stack * stack = state.stack;
		MPI * interfaceMPI = OBJECT_IFACE(MPI);
		interfaceMPI->push(&group->A);
		return 1;
	}
	int ECPGroup::getB(State & state, mbedtls_ecp_group * group){
		Stack * stack = state.stack;
		MPI * interfaceMPI = OBJECT_IFACE(MPI);
		interfaceMPI->push(&group->B);
		return 1;
	}
	int ECPGroup::getG(State & state, mbedtls_ecp_group * group){
		Stack * stack = state.stack;
		ECPPoint * interfaceECPPoint = OBJECT_IFACE(ECPPoint);
		interfaceECPPoint->push(&group->G);
		return 1;
	}
	int ECPGroup::getN(State & state, mbedtls_ecp_group * group){
		Stack * stack = state.stack;
		MPI * interfaceMPI = OBJECT_IFACE(MPI);
		interfaceMPI->push(&group->N);
		return 1;
	}
	int ECPGroup::getPBits(State & state, mbedtls_ecp_group * group){
		Stack * stack = state.stack;
		stack->push<int>(group->pbits);
		return 1;
	}
	int ECPGroup::getNBits(State & state, mbedtls_ecp_group * group){
		Stack * stack = state.stack;
		stack->push<int>(group->nbits);
		return 1;
	}
	int ECPGroup::geth(State & state, mbedtls_ecp_group * group){
		Stack * stack = state.stack;
		stack->push<int>(group->h);
		return 1;
	}
	int ECPGroup::getT(State & state, mbedtls_ecp_group * group){
		Stack * stack = state.stack;
		ECPPoint * interfaceECPPoint = OBJECT_IFACE(ECPPoint);
		interfaceECPPoint->push(group->T);
		return 1;
	}
	int ECPGroup::getTSize(State & state, mbedtls_ecp_group * group){
		Stack * stack = state.stack;
		stack->push<int>(group->T_size);
		return 1;
	}

	int ECPGroup::copy(State & state, mbedtls_ecp_group * group){
		Stack * stack = state.stack;
		ECPGroup * interfaceECPGroup = OBJECT_IFACE(ECPGroup);
		mbedtls_ecp_group * src = interfaceECPGroup->get(1);
		if (src){
			stack->push<int>(mbedtls_ecp_group_copy(group, src));
			return 1;
		}
		return 0;
	}

	int ECPGroup::load(State & state, mbedtls_ecp_group * group){
		Stack * stack = state.stack;
		if (stack->is<LUA_TNUMBER>(1)){
			stack->push<int>(mbedtls_ecp_group_load(group, static_cast<mbedtls_ecp_group_id>(stack->to<int>(1))));
			return 1;
		}
		return 0;
	}

	int ECPGroup::read(State & state, mbedtls_ecp_group * group){
		Stack * stack = state.stack;
		if (stack->is<LUA_TSTRING>(1)){
			const std::string value = stack->toLString(1);
			const unsigned char* input = reinterpret_cast<const unsigned char*>(value.c_str());
			stack->push<int>(mbedtls_ecp_tls_read_group(group, &input, value.length()));
			return 1;
		}
		return 0;
	}

	int ECPGroup::write(State & state, mbedtls_ecp_group * group){
		Stack * stack = state.stack;
		if (stack->is<LUA_TNUMBER>(1)){
			const size_t outputMaxLength = stack->to<int>(1);
			size_t outputLength = 0;
			unsigned char * buffer = new unsigned char[outputMaxLength];
			int result = mbedtls_ecp_tls_write_group(group, &outputLength, buffer, outputMaxLength);
			if (result == 0){
				stack->pushLString(std::string(reinterpret_cast<char *>(buffer), outputLength));
			}
			else{
				stack->push<int>(result);
			}
			return 1;
		}
		return 0;
	}

	int ECPGroup::mul(State & state, mbedtls_ecp_group * group){
		Stack * stack = state.stack;
		ECPPoint * interfaceECPPoint = OBJECT_IFACE(ECPPoint);
		CTRDRBGContext * interfaceCTRDRBGContext = OBJECT_IFACE(CTRDRBGContext);
		MPI * interfaceMPI = OBJECT_IFACE(MPI);

		mbedtls_ecp_point * R = interfaceECPPoint->get(1);
		mbedtls_mpi * m = interfaceMPI->get(2);
		mbedtls_ecp_point * P = interfaceECPPoint->get(3);
		mbedtls_ctr_drbg_context * drbg = interfaceCTRDRBGContext->get(4);

		if (drbg && R && m && P){
			stack->push<int>(mbedtls_ecp_mul(group, R, m, P, mbedtls_ctr_drbg_random, drbg));
			return 1;
		}
		return 0;
	}

	int ECPGroup::mulAdd(State & state, mbedtls_ecp_group * group){
		Stack * stack = state.stack;
		ECPPoint * interfaceECPPoint = OBJECT_IFACE(ECPPoint);
		MPI * interfaceMPI = OBJECT_IFACE(MPI);

		mbedtls_ecp_point * R = interfaceECPPoint->get(1);
		mbedtls_mpi * m = interfaceMPI->get(2);
		mbedtls_ecp_point * P = interfaceECPPoint->get(3);
		mbedtls_mpi * n = interfaceMPI->get(4);
		mbedtls_ecp_point * Q = interfaceECPPoint->get(5);

		if (R && m && P && n && Q){
			stack->push<int>(mbedtls_ecp_muladd(group, R, m, P, n, Q));
			return 1;
		}
		return 0;
	}

	int ECPGroup::checkPubKey(State & state, mbedtls_ecp_group * group){
		Stack * stack = state.stack;
		ECPPoint * interfaceECPPoint = OBJECT_IFACE(ECPPoint);
		mbedtls_ecp_point * pt = interfaceECPPoint->get(1);
		if (pt){
			stack->push<int>(mbedtls_ecp_check_pubkey(group, pt));
			return 1;
		}
		return 0;
	}
	int ECPGroup::checkPrivKey(State & state, mbedtls_ecp_group * group){
		Stack * stack = state.stack;
		MPI * interfaceMPI = OBJECT_IFACE(MPI);
		mbedtls_mpi * d = interfaceMPI->get(2);
		if (d){
			stack->push<int>(mbedtls_ecp_check_privkey(group, d));
			return 1;
		}
		return 0;
	}

	int ECPGroup::genKeyPair(State & state, mbedtls_ecp_group * group){
		Stack * stack = state.stack;
		MPI * interfaceMPI = OBJECT_IFACE(MPI);
		ECPPoint * interfaceECPPoint = OBJECT_IFACE(ECPPoint);
		CTRDRBGContext * interfaceCTRDRBGContext = OBJECT_IFACE(CTRDRBGContext);

		mbedtls_mpi * d = new mbedtls_mpi;
		mbedtls_ecp_point * Q = new mbedtls_ecp_point;

		mbedtls_mpi_init(d);
		mbedtls_ecp_point_init(Q);

		mbedtls_ctr_drbg_context * drbg = interfaceCTRDRBGContext->get(1);

		if (d && Q && drbg){
			int result = mbedtls_ecp_gen_keypair(group, d, Q, mbedtls_ctr_drbg_random, drbg);
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

	void initECPGroup(State * state, Module & module){
		INIT_OBJECT(ECPGroup);
	}
};
