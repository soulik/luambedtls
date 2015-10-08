#include "objects/ECPCurveInfo.hpp"

namespace luambedtls {
	mbedtls_ecp_curve_info * ECPCurveInfo::constructor(State & state, bool & managed){
		mbedtls_ecp_curve_info * info = new mbedtls_ecp_curve_info;
		return info;
	}

	void ECPCurveInfo::destructor(State & state, mbedtls_ecp_curve_info * info){
		delete info;
	}

	int ECPCurveInfo::getGroupID(State & state, mbedtls_ecp_curve_info * info){
		Stack * stack = state.stack;
		stack->push<int>(info->grp_id);
		return 1;
	}
	int ECPCurveInfo::getTLSID(State & state, mbedtls_ecp_curve_info * info){
		Stack * stack = state.stack;
		stack->push<int>(info->tls_id);
		return 1;
	}
	int ECPCurveInfo::getBitSize(State & state, mbedtls_ecp_curve_info * info){
		Stack * stack = state.stack;
		stack->push<int>(info->bit_size);
		return 1;
	}
	int ECPCurveInfo::getName(State & state, mbedtls_ecp_curve_info * info){
		Stack * stack = state.stack;
		stack->push<const std::string &>(info->name);
		return 1;
	}

	void initECPCurveInfo(State * state, Module & module){
		INIT_OBJECT(ECPCurveInfo);
	}
};
