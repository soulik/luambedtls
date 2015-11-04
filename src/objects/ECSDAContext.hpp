#ifndef LUA_MBEDTLS_OBJECTS_ECSDACONTEXT_H
#define LUA_MBEDTLS_OBJECTS_ECSDACONTEXT_H

#include "common.hpp"

namespace luambedtls {
	struct ecsda_wrapper {
		mbedtls_ecdsa_context * context;
	};

	class ECSDAContext : public Object<ecsda_wrapper> {
	public:
		explicit ECSDAContext(State * state) : Object<ecsda_wrapper>(state){
			LUTOK_METHOD("sign", &ECSDAContext::sign);
			LUTOK_METHOD("signDet", &ECSDAContext::signDet);
			LUTOK_METHOD("verify", &ECSDAContext::verify);
			LUTOK_METHOD("writeSignature", &ECSDAContext::writeSignature);
			LUTOK_METHOD("writeSignatureDet", &ECSDAContext::writeSignatureDet);
			LUTOK_METHOD("readSignature", &ECSDAContext::readSignature);
			LUTOK_METHOD("genKey", &ECSDAContext::genKey);
			LUTOK_METHOD("fromKeypair", &ECSDAContext::fromKeypair);
			LUTOK_PROPERTY("keypair", &ECSDAContext::getKeypair, &ECSDAContext::nullMethod);
		}

		ecsda_wrapper * constructor(State & state, bool & managed);

		void destructor(State & state, ecsda_wrapper * context);

		int sign(State & state, ecsda_wrapper * context);
		int signDet(State & state, ecsda_wrapper * context);
		int verify(State & state, ecsda_wrapper * context);
		int writeSignature(State & state, ecsda_wrapper * context);
		int writeSignatureDet(State & state, ecsda_wrapper * context);
		int readSignature(State & state, ecsda_wrapper * context);
		int genKey(State & state, ecsda_wrapper * context);
		int fromKeypair(State & state, ecsda_wrapper * context);
		int getKeypair(State & state, ecsda_wrapper * context);
	};
	void initECSDAContext(State*, Module&);
};
#endif	
