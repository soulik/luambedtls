#include "objects/ECPKeyPair.hpp"
#include "objects/ECPGroup.hpp"
#include "objects/ECPPoint.hpp"
#include "objects/ECPCurveInfo.hpp"
#include "objects/MPI.hpp"
#include "objects/CTRDRBGContext.hpp"

namespace luambedtls {
	mbedtls_ecp_keypair * ECPKeyPair::constructor(State & state, bool & managed){
		mbedtls_ecp_keypair * keyPair = new mbedtls_ecp_keypair;
		mbedtls_ecp_keypair_init(keyPair);
		return keyPair;
	}

	void ECPKeyPair::destructor(State & state, mbedtls_ecp_keypair * keyPair){
		mbedtls_ecp_keypair_free(keyPair);
		delete keyPair;
	}

	int ECPKeyPair::getGroup(State & state, mbedtls_ecp_keypair * keyPair){
		Stack * stack = state.stack;
		ECPGroup * interfaceECPGroup = OBJECT_IFACE(ECPGroup);
		interfaceECPGroup->push(&keyPair->grp);
		return 1;
	}
	int ECPKeyPair::getd(State & state, mbedtls_ecp_keypair * keyPair){
		Stack * stack = state.stack;
		MPI * interfaceMPI = OBJECT_IFACE(MPI);
		interfaceMPI->push(&keyPair->d);
		return 1;
	}
	int ECPKeyPair::getQ(State & state, mbedtls_ecp_keypair * keyPair){
		Stack * stack = state.stack;
		ECPPoint * interfaceECPPoint = OBJECT_IFACE(ECPPoint);
		interfaceECPPoint->push(&keyPair->Q);
		return 1;
	}
	int ECPKeyPair::setGroup(State & state, mbedtls_ecp_keypair * keyPair){
		Stack * stack = state.stack;
		ECPGroup * interfaceECPGroup = OBJECT_IFACE(ECPGroup);
		mbedtls_ecp_group * group = interfaceECPGroup->get(1);
		if (group){
			mbedtls_ecp_group_copy(&keyPair->grp, group);
		}
		return 0;
	}
	int ECPKeyPair::setd(State & state, mbedtls_ecp_keypair * keyPair){
		Stack * stack = state.stack;
		MPI * interfaceMPI = OBJECT_IFACE(MPI);
		mbedtls_mpi * d = interfaceMPI->get(1);
		if (d){
			mbedtls_mpi_copy(&keyPair->d, d);
		}
		return 0;
	}
	int ECPKeyPair::setQ(State & state, mbedtls_ecp_keypair * keyPair){
		Stack * stack = state.stack;
		ECPPoint * interfaceECPPoint = OBJECT_IFACE(ECPPoint);
		mbedtls_ecp_point * Q = interfaceECPPoint->get(1);
		if (Q){
			mbedtls_ecp_copy(&keyPair->Q, Q);
		}
		return 0;
	}

	int ECPKeyPair::genKey(State & state, mbedtls_ecp_keypair * keyPair){
		Stack * stack = state.stack;
		CTRDRBGContext * interfaceCTRDRBGContext = OBJECT_IFACE(CTRDRBGContext);

		if (stack->is<LUA_TNUMBER>(1)){
			mbedtls_ctr_drbg_context * drbg = interfaceCTRDRBGContext->get(2);

			if (drbg){
				stack->push<int>(mbedtls_ecp_gen_key(static_cast<mbedtls_ecp_group_id>(stack->to<int>(1)), keyPair, mbedtls_ctr_drbg_random, drbg));
				return 1;
			}
		}
		return 0;
	}

	int ECPKeyPair::checkPubPriv(State & state, mbedtls_ecp_keypair * keyPair){
		Stack * stack = state.stack;
		ECPKeyPair * interfaceECPKeyPair = OBJECT_IFACE(ECPKeyPair);
		mbedtls_ecp_keypair * keyPairPriv = interfaceECPKeyPair->get(1);
		if (keyPairPriv){
			stack->push<int>(mbedtls_ecp_check_pub_priv(keyPair, keyPairPriv));
			return 1;
		}
		return 0;
	}

	int ECPCurveList(State & state){
		Stack * stack = state.stack;
		ECPCurveInfo * interfaceECPCurveInfo = OBJECT_IFACE(ECPCurveInfo);
		const mbedtls_ecp_curve_info * list = mbedtls_ecp_curve_list();
		stack->newTable();
		
		int i = 0;
		const mbedtls_ecp_curve_info * info = &list[i];
		while (info != nullptr && info->tls_id != MBEDTLS_ECP_DP_NONE) {
			stack->push<int>(i+1);
			interfaceECPCurveInfo->push(const_cast<mbedtls_ecp_curve_info *>(info));
			stack->setTable(-3);
			info = &list[++i];
		};
		return 1;
	}
	
	int ECPGroupIDList(State & state){
		Stack * stack = state.stack;
		const mbedtls_ecp_group_id * list = mbedtls_ecp_grp_id_list();
		stack->newTable();

		int i = 0;
		mbedtls_ecp_group_id id = list[i];
		while (id != MBEDTLS_ECP_DP_NONE) {
			stack->push<int>(i + 1);
			stack->push<int>(id);
			stack->setTable(-3);
			id = list[++i];
		};
		return 1;
	}

	int ECPCurveInfoFromGroupID(State & state){
		Stack * stack = state.stack;
		ECPCurveInfo * interfaceECPCurveInfo = OBJECT_IFACE(ECPCurveInfo);
		if (stack->is<LUA_TNUMBER>(1)){
			const mbedtls_ecp_curve_info * info = mbedtls_ecp_curve_info_from_grp_id(static_cast<mbedtls_ecp_group_id>(stack->to<int>(1)));
			if (info){
				interfaceECPCurveInfo->push(const_cast<mbedtls_ecp_curve_info *>(info));
			}
			else{
				stack->push<bool>(false);
			}
			return 1;
		}
		return 0;
	}

	int ECPCurveInfoFromTLSID(State & state){
		Stack * stack = state.stack;
		ECPCurveInfo * interfaceECPCurveInfo = OBJECT_IFACE(ECPCurveInfo);
		if (stack->is<LUA_TNUMBER>(1)){
			const mbedtls_ecp_curve_info * info = mbedtls_ecp_curve_info_from_tls_id(stack->to<int>(1));
			if (info){
				interfaceECPCurveInfo->push(const_cast<mbedtls_ecp_curve_info *>(info));
			}
			else{
				stack->push<bool>(false);
			}
			return 1;
		}
		return 0;
	}

	int ECPCurveInfoFromName(State & state){
		Stack * stack = state.stack;
		ECPCurveInfo * interfaceECPCurveInfo = OBJECT_IFACE(ECPCurveInfo);
		if (stack->is<LUA_TSTRING>(1)){
			const std::string name = stack->to<const std::string>(1);
			const mbedtls_ecp_curve_info * info = mbedtls_ecp_curve_info_from_name(name.c_str());
			if (info){
				interfaceECPCurveInfo->push(const_cast<mbedtls_ecp_curve_info *>(info));
			}
			else{
				stack->push<bool>(false);
			}
			return 1;
		}
		return 0;
	}

	static int ECPSelfTest(State & state){
		Stack * stack = state.stack;
		stack->push<int>(mbedtls_ecp_self_test(stack->to<int>(1)));
		return 1;
	}


	void initECPKeyPair(State * state, Module & module){
		INIT_OBJECT(ECPKeyPair);
		module["ECPSelfTest"] = ECPSelfTest;
		module["ECPCurveList"] = ECPCurveList;
		module["ECPGroupIDList"] = ECPGroupIDList;
		module["ECPCurveInfoFromGroupID"] = ECPCurveInfoFromGroupID;
		module["ECPCurveInfoFromTLSID"] = ECPCurveInfoFromTLSID;
		module["ECPCurveInfoFromName"] = ECPCurveInfoFromName;
	}
};
