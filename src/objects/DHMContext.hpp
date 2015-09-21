#ifndef LUA_MBEDTLS_OBJECTS_DHMCONTEXT_H
#define LUA_MBEDTLS_OBJECTS_DHMCONTEXT_H

#include "common.hpp"

namespace luambedtls {
	class DHMContext : public Object<mbedtls_dhm_context> {
	public:
		explicit DHMContext(State * state) : Object<mbedtls_dhm_context>(state){
			LUTOK_METHOD("readParams", &DHMContext::readParams);
			LUTOK_METHOD("makeParams", &DHMContext::makeParams);
			LUTOK_METHOD("readPublic", &DHMContext::readPublic);
			LUTOK_METHOD("makePublic", &DHMContext::makePublic);
			LUTOK_METHOD("calcSecret", &DHMContext::calcSecret);
			LUTOK_METHOD("parseDHM", &DHMContext::parseDHM);
			LUTOK_METHOD("parseDHMFile", &DHMContext::parseDHMFile);

			LUTOK_PROPERTY("len", &DHMContext::getLen, &DHMContext::setLen);
			LUTOK_PROPERTY("P", &DHMContext::getP, &DHMContext::setP);
			LUTOK_PROPERTY("G", &DHMContext::getG, &DHMContext::setG);
			LUTOK_PROPERTY("X", &DHMContext::getX, &DHMContext::setX);
			LUTOK_PROPERTY("GX", &DHMContext::getGX, &DHMContext::setGX);
			LUTOK_PROPERTY("GY", &DHMContext::getGY, &DHMContext::setGY);
			LUTOK_PROPERTY("K", &DHMContext::getK, &DHMContext::setK);
			LUTOK_PROPERTY("RP", &DHMContext::getRP, &DHMContext::setRP);
			LUTOK_PROPERTY("Vi", &DHMContext::getVi, &DHMContext::setVi);
			LUTOK_PROPERTY("Vf", &DHMContext::getVf, &DHMContext::setVf);
			LUTOK_PROPERTY("pX", &DHMContext::getpX, &DHMContext::setpX);
		}

		mbedtls_dhm_context * constructor(State & state, bool & managed);

		void destructor(State & state, mbedtls_dhm_context * context);

		int readParams(State & state, mbedtls_dhm_context * context);
		int makeParams(State & state, mbedtls_dhm_context * context);
		int readPublic(State & state, mbedtls_dhm_context * context);
		int makePublic(State & state, mbedtls_dhm_context * context);
		int calcSecret(State & state, mbedtls_dhm_context * context);
		int parseDHM(State & state, mbedtls_dhm_context * context);
		int parseDHMFile(State & state, mbedtls_dhm_context * context);

		int getLen(State & state, mbedtls_dhm_context * context);
		int setLen(State & state, mbedtls_dhm_context * context);
		int getP(State & state, mbedtls_dhm_context * context);
		int setP(State & state, mbedtls_dhm_context * context);
		int getG(State & state, mbedtls_dhm_context * context);
		int setG(State & state, mbedtls_dhm_context * context);
		int getX(State & state, mbedtls_dhm_context * context);
		int setX(State & state, mbedtls_dhm_context * context);
		int getGX(State & state, mbedtls_dhm_context * context);
		int setGX(State & state, mbedtls_dhm_context * context);
		int getGY(State & state, mbedtls_dhm_context * context);
		int setGY(State & state, mbedtls_dhm_context * context);
		int getK(State & state, mbedtls_dhm_context * context);
		int setK(State & state, mbedtls_dhm_context * context);
		int getRP(State & state, mbedtls_dhm_context * context);
		int setRP(State & state, mbedtls_dhm_context * context);
		int getVi(State & state, mbedtls_dhm_context * context);
		int setVi(State & state, mbedtls_dhm_context * context);
		int getVf(State & state, mbedtls_dhm_context * context);
		int setVf(State & state, mbedtls_dhm_context * context);
		int getpX(State & state, mbedtls_dhm_context * context);
		int setpX(State & state, mbedtls_dhm_context * context);
	};
};

#endif	
