#ifndef LUA_MBEDTLS_OBJECTS_ECDHCONTEXT_H
#define LUA_MBEDTLS_OBJECTS_ECDHCONTEXT_H

#include "common.hpp"

namespace luambedtls {
	class ECDHContext : public Object<mbedtls_ecdh_context> {
	public:
		explicit ECDHContext(State * state) : Object<mbedtls_ecdh_context>(state){
			LUTOK_METHOD("genPublic", &ECDHContext::genPublic);
			LUTOK_METHOD("computeShared", &ECDHContext::computeShared);
			LUTOK_METHOD("makeParams", &ECDHContext::makeParams);
			LUTOK_METHOD("readParams", &ECDHContext::readParams);
			LUTOK_METHOD("getParams", &ECDHContext::getParams);
			LUTOK_METHOD("makePublic", &ECDHContext::makePublic);
			LUTOK_METHOD("readPublic", &ECDHContext::readPublic);
			LUTOK_METHOD("calcSecret", &ECDHContext::calcSecret);

			LUTOK_PROPERTY("group", &ECDHContext::getGroup, &ECDHContext::setGroup);
			LUTOK_PROPERTY("d", &ECDHContext::getd, &ECDHContext::setd);
			LUTOK_PROPERTY("Q", &ECDHContext::getQ, &ECDHContext::setQ);
			LUTOK_PROPERTY("Qp", &ECDHContext::getQp, &ECDHContext::setQp);
			LUTOK_PROPERTY("z", &ECDHContext::getz, &ECDHContext::setz);
			LUTOK_PROPERTY("pointFormat", &ECDHContext::getPointFormat, &ECDHContext::setPointFormat);
			LUTOK_PROPERTY("Vi", &ECDHContext::getVi, &ECDHContext::setVi);
			LUTOK_PROPERTY("Vf", &ECDHContext::getVf, &ECDHContext::setVf);
		}

		mbedtls_ecdh_context * constructor(State & state, bool & managed);

		void destructor(State & state, mbedtls_ecdh_context * context);

		int genPublic(State & state, mbedtls_ecdh_context * context);
		int computeShared(State & state, mbedtls_ecdh_context * context);
		int makeParams(State & state, mbedtls_ecdh_context * context);
		int readParams(State & state, mbedtls_ecdh_context * context);
		int getParams(State & state, mbedtls_ecdh_context * context);
		int makePublic(State & state, mbedtls_ecdh_context * context);
		int readPublic(State & state, mbedtls_ecdh_context * context);
		int calcSecret(State & state, mbedtls_ecdh_context * context);

		int getGroup(State & state, mbedtls_ecdh_context * context);
		int getd(State & state, mbedtls_ecdh_context * context);
		int getQ(State & state, mbedtls_ecdh_context * context);
		int getQp(State & state, mbedtls_ecdh_context * context);
		int getz(State & state, mbedtls_ecdh_context * context);
		int getPointFormat(State & state, mbedtls_ecdh_context * context);
		int getVi(State & state, mbedtls_ecdh_context * context);
		int getVf(State & state, mbedtls_ecdh_context * context);
		
		int setGroup(State & state, mbedtls_ecdh_context * context);
		int setd(State & state, mbedtls_ecdh_context * context);
		int setQ(State & state, mbedtls_ecdh_context * context);
		int setQp(State & state, mbedtls_ecdh_context * context);
		int setz(State & state, mbedtls_ecdh_context * context);
		int setPointFormat(State & state, mbedtls_ecdh_context * context);
		int setVi(State & state, mbedtls_ecdh_context * context);
		int setVf(State & state, mbedtls_ecdh_context * context);
	};
};

#endif	
