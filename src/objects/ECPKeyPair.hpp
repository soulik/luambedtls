#ifndef LUA_MBEDTLS_OBJECTS_ECPKEYPAIR_H
#define LUA_MBEDTLS_OBJECTS_ECPKEYPAIR_H

#include "common.hpp"

namespace luambedtls {
	class ECPKeyPair : public Object<mbedtls_ecp_keypair> {
	public:
		explicit ECPKeyPair(State * state) : Object<mbedtls_ecp_keypair>(state){
			LUTOK_PROPERTY("group", &ECPKeyPair::getGroup, &ECPKeyPair::setGroup);
			LUTOK_PROPERTY("d", &ECPKeyPair::getd, &ECPKeyPair::setd);
			LUTOK_PROPERTY("Q", &ECPKeyPair::getQ, &ECPKeyPair::setQ);

			LUTOK_METHOD("genKey", &ECPKeyPair::genKey);
			LUTOK_METHOD("checkPubPriv", &ECPKeyPair::checkPubPriv);
		}

		mbedtls_ecp_keypair * constructor(State & state, bool & managed);

		void destructor(State & state, mbedtls_ecp_keypair * keyPair);

		int genKey(State & state, mbedtls_ecp_keypair * keyPair);
		int checkPubPriv(State & state, mbedtls_ecp_keypair * keyPair);

		int getGroup(State & state, mbedtls_ecp_keypair * keyPair);
		int getd(State & state, mbedtls_ecp_keypair * keyPair);
		int getQ(State & state, mbedtls_ecp_keypair * keyPair);
		int setGroup(State & state, mbedtls_ecp_keypair * keyPair);
		int setd(State & state, mbedtls_ecp_keypair * keyPair);
		int setQ(State & state, mbedtls_ecp_keypair * keyPair);

	};
	void initECPKeyPair(State*, Module&);
	
	int ECPCurveList(State&);
	int ECPGroupIDList(State&);
	int ECPCurveInfoFromGroupID(State&);
	int ECPCurveInfoFromTLSID(State&);
	int ECPCurveInfoFromName(State&);
};
#endif	
