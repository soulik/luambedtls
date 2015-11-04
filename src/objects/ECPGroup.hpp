#ifndef LUA_MBEDTLS_OBJECTS_ECPGROUP_H
#define LUA_MBEDTLS_OBJECTS_ECPGROUP_H

#include "common.hpp"

namespace luambedtls {
	class ECPGroup : public Object<mbedtls_ecp_group> {
	public:
		explicit ECPGroup(State * state) : Object<mbedtls_ecp_group>(state){
			LUTOK_PROPERTY("id", &ECPGroup::getGroupID, &ECPGroup::nullMethod);
			LUTOK_PROPERTY("P", &ECPGroup::getP, &ECPGroup::nullMethod);
			LUTOK_PROPERTY("A", &ECPGroup::getA, &ECPGroup::nullMethod);
			LUTOK_PROPERTY("B", &ECPGroup::getB, &ECPGroup::nullMethod);
			LUTOK_PROPERTY("G", &ECPGroup::getG, &ECPGroup::nullMethod);
			LUTOK_PROPERTY("N", &ECPGroup::getN, &ECPGroup::nullMethod);
			LUTOK_PROPERTY("PBits", &ECPGroup::getPBits, &ECPGroup::nullMethod);
			LUTOK_PROPERTY("NBits", &ECPGroup::getNBits, &ECPGroup::nullMethod);
			LUTOK_PROPERTY("h", &ECPGroup::geth, &ECPGroup::nullMethod);
			LUTOK_PROPERTY("T", &ECPGroup::getT, &ECPGroup::nullMethod);
			LUTOK_PROPERTY("TSize", &ECPGroup::getTSize, &ECPGroup::nullMethod);

			LUTOK_METHOD("copy", &ECPGroup::copy);
			LUTOK_METHOD("load", &ECPGroup::load);
			LUTOK_METHOD("read", &ECPGroup::read);
			LUTOK_METHOD("write", &ECPGroup::write);

			LUTOK_METHOD("mul", &ECPGroup::mul);
			LUTOK_METHOD("mulAdd", &ECPGroup::mulAdd);

			LUTOK_METHOD("checkPubKey", &ECPGroup::checkPubKey);
			LUTOK_METHOD("checkPrivKey", &ECPGroup::checkPrivKey);

			LUTOK_METHOD("genKeyPair", &ECPGroup::genKeyPair);
		}

		mbedtls_ecp_group * constructor(State & state, bool & managed);

		void destructor(State & state, mbedtls_ecp_group * group);

		int copy(State & state, mbedtls_ecp_group * group);

		int load(State & state, mbedtls_ecp_group * group);
		int read(State & state, mbedtls_ecp_group * group);
		int write(State & state, mbedtls_ecp_group * group);

		int mul(State & state, mbedtls_ecp_group * group);
		int mulAdd(State & state, mbedtls_ecp_group * group);

		int checkPubKey(State & state, mbedtls_ecp_group * group);
		int checkPrivKey(State & state, mbedtls_ecp_group * group);

		int genKeyPair(State & state, mbedtls_ecp_group * group);

		int getGroupID(State & state, mbedtls_ecp_group * group);
		int getP(State & state, mbedtls_ecp_group * group);
		int getA(State & state, mbedtls_ecp_group * group);
		int getB(State & state, mbedtls_ecp_group * group);
		int getG(State & state, mbedtls_ecp_group * group);
		int getN(State & state, mbedtls_ecp_group * group);
		int getPBits(State & state, mbedtls_ecp_group * group);
		int getNBits(State & state, mbedtls_ecp_group * group);
		int geth(State & state, mbedtls_ecp_group * group);
		int getT(State & state, mbedtls_ecp_group * group);
		int getTSize(State & state, mbedtls_ecp_group * group);
	};
	void initECPGroup(State*, Module&);
};
#endif	
