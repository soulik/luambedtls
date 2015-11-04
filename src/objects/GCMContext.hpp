#ifndef LUA_MBEDTLS_OBJECTS_GCMCONTEXT_H
#define LUA_MBEDTLS_OBJECTS_GCMCONTEXT_H

#include "common.hpp"

namespace luambedtls {
	class GCMContext : public Object<mbedtls_gcm_context> {
	public:
		explicit GCMContext(State * state) : Object<mbedtls_gcm_context>(state){
			LUTOK_METHOD("setKey", &GCMContext::setKey);
			LUTOK_METHOD("cryptAndTag", &GCMContext::cryptAndTag);
			LUTOK_METHOD("authDecrypt", &GCMContext::authDecrypt);
			LUTOK_METHOD("starts", &GCMContext::starts);
			LUTOK_METHOD("update", &GCMContext::update);
			LUTOK_METHOD("finish", &GCMContext::finish);
		}

		mbedtls_gcm_context * constructor(State & state, bool & managed);

		void destructor(State & state, mbedtls_gcm_context * context);

		int setKey(State & state, mbedtls_gcm_context * context);
		int cryptAndTag(State & state, mbedtls_gcm_context * context);
		int authDecrypt(State & state, mbedtls_gcm_context * context);
		int starts(State & state, mbedtls_gcm_context * context);
		int update(State & state, mbedtls_gcm_context * context);
		int finish(State & state, mbedtls_gcm_context * context);
	};
	void initGCMContext(State*, Module&);
	int GCMSelfTest(State&);
};
#endif	
