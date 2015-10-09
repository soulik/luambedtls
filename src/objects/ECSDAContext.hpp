#ifndef LUA_MBEDTLS_OBJECTS_ECSDACONTEXT_H
#define LUA_MBEDTLS_OBJECTS_ECSDACONTEXT_H

#include "common.hpp"

namespace luambedtls {
	class ECSDAContext : public Object<mbedtls_ecdsa_context> {
	public:
		explicit ECSDAContext(State * state) : Object<mbedtls_ecdsa_context>(state){
			LUTOK_METHOD("sign", &ECSDAContext::sign);
			LUTOK_METHOD("signDet", &ECSDAContext::signDet);
			LUTOK_METHOD("verify", &ECSDAContext::verify);
			LUTOK_METHOD("writeSignature", &ECSDAContext::writeSignature);
			LUTOK_METHOD("writeSignatureDet", &ECSDAContext::writeSignatureDet);
			LUTOK_METHOD("readSignature", &ECSDAContext::readSignature);
			LUTOK_METHOD("genKey", &ECSDAContext::genKey);
			LUTOK_METHOD("fromKeypair", &ECSDAContext::fromKeypair);
		}

		mbedtls_ecdsa_context * constructor(State & state, bool & managed);

		void destructor(State & state, mbedtls_ecdsa_context * context);

		int sign(State & state, mbedtls_ecdsa_context * context);
		int signDet(State & state, mbedtls_ecdsa_context * context);
		int verify(State & state, mbedtls_ecdsa_context * context);
		int writeSignature(State & state, mbedtls_ecdsa_context * context);
		int writeSignatureDet(State & state, mbedtls_ecdsa_context * context);
		int readSignature(State & state, mbedtls_ecdsa_context * context);
		int genKey(State & state, mbedtls_ecdsa_context * context);
		int fromKeypair(State & state, mbedtls_ecdsa_context * context);
	};
};

#endif	
