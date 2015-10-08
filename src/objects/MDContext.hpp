#ifndef LUA_MBEDTLS_OBJECTS_MDCONTEXT_H
#define LUA_MBEDTLS_OBJECTS_MDCONTEXT_H

#include "common.hpp"

namespace luambedtls {
	class MDContext : public Object<mbedtls_md_context_t> {
	public:
		explicit MDContext(State * state) : Object<mbedtls_md_context_t>(state){
			LUTOK_METHOD("clone", &MDContext::clone);
			LUTOK_METHOD("setup", &MDContext::setup);

			LUTOK_METHOD("starts", &MDContext::starts);
			LUTOK_METHOD("update", &MDContext::update);
			LUTOK_METHOD("finish", &MDContext::finish);

			LUTOK_METHOD("HMACstarts", &MDContext::HMACstarts);
			LUTOK_METHOD("HMACupdate", &MDContext::HMACupdate);
			LUTOK_METHOD("HMACfinish", &MDContext::HMACfinish);
			LUTOK_METHOD("HMACreset", &MDContext::HMACreset);
		}

		mbedtls_md_context_t * constructor(State & state, bool & managed);

		void destructor(State & state, mbedtls_md_context_t * context);

		int clone(State & state, mbedtls_md_context_t * context);
		int setup(State & state, mbedtls_md_context_t * context);

		int starts(State & state, mbedtls_md_context_t * context);
		int update(State & state, mbedtls_md_context_t * context);
		int finish(State & state, mbedtls_md_context_t * context);

		int HMACstarts(State & state, mbedtls_md_context_t * context);
		int HMACupdate(State & state, mbedtls_md_context_t * context);
		int HMACfinish(State & state, mbedtls_md_context_t * context);
		int HMACreset(State & state, mbedtls_md_context_t * context);
	};
};

#endif	
