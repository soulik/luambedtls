#ifndef LUA_MBEDTLS_OBJECTS_ECPCURVEINFO_H
#define LUA_MBEDTLS_OBJECTS_ECPCURVEINFO_H

#include "common.hpp"

namespace luambedtls {
	class ECPCurveInfo : public Object<mbedtls_ecp_curve_info> {
	public:
		explicit ECPCurveInfo(State * state) : Object<mbedtls_ecp_curve_info>(state){
			LUTOK_PROPERTY("groupID", &ECPCurveInfo::getGroupID, &ECPCurveInfo::nullMethod);
			LUTOK_PROPERTY("TLSID", &ECPCurveInfo::getTLSID, &ECPCurveInfo::nullMethod);
			LUTOK_PROPERTY("bitSize", &ECPCurveInfo::getBitSize, &ECPCurveInfo::nullMethod);
			LUTOK_PROPERTY("name", &ECPCurveInfo::getName, &ECPCurveInfo::nullMethod);
		}

		mbedtls_ecp_curve_info * constructor(State & state, bool & managed);

		void destructor(State & state, mbedtls_ecp_curve_info * info);

		int getGroupID(State & state, mbedtls_ecp_curve_info * info);
		int getTLSID(State & state, mbedtls_ecp_curve_info * info);
		int getBitSize(State & state, mbedtls_ecp_curve_info * info);
		int getName(State & state, mbedtls_ecp_curve_info * info);

	};
	void initECPCurveInfo(State*, Module&);
};
#endif	
