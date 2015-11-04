#ifndef LUA_MBEDTLS_OBJECTS_CTRDRBGCONTEXT_H
#define LUA_MBEDTLS_OBJECTS_CTRDRBGCONTEXT_H

#include "common.hpp"

namespace luambedtls {
	class CTRDRBGContext : public Object<mbedtls_ctr_drbg_context> {
	public:
		explicit CTRDRBGContext(State * state) : Object<mbedtls_ctr_drbg_context>(state){
			LUTOK_METHOD("seed", &CTRDRBGContext::seed);
			LUTOK_METHOD("reseed", &CTRDRBGContext::reseed);
			LUTOK_METHOD("update", &CTRDRBGContext::update);
			LUTOK_METHOD("randomWithAdd", &CTRDRBGContext::randomWithAdd);
			LUTOK_METHOD("random", &CTRDRBGContext::random);
			LUTOK_METHOD("writeSeedFile", &CTRDRBGContext::writeSeedFile);
			LUTOK_METHOD("updateFromSeedFile", &CTRDRBGContext::updateFromSeedFile);

			LUTOK_PROPERTY("predictionResistance", &CTRDRBGContext::nullMethod, &CTRDRBGContext::setPredictionResistance);
			LUTOK_PROPERTY("length", &CTRDRBGContext::nullMethod, &CTRDRBGContext::setLength);
			LUTOK_PROPERTY("reseedInterval", &CTRDRBGContext::nullMethod, &CTRDRBGContext::setReseedInterval);
		}

		mbedtls_ctr_drbg_context * constructor(State & state, bool & managed);

		void destructor(State & state, mbedtls_ctr_drbg_context * ctr_drbg_context);

		int seed(State & state, mbedtls_ctr_drbg_context * ctr_drbg_context);

		int setPredictionResistance(State & state, mbedtls_ctr_drbg_context * ctr_drbg_context);
		int setLength(State & state, mbedtls_ctr_drbg_context * ctr_drbg_context);
		int setReseedInterval(State & state, mbedtls_ctr_drbg_context * ctr_drbg_context);

		int reseed(State & state, mbedtls_ctr_drbg_context * ctr_drbg_context);
		int update(State & state, mbedtls_ctr_drbg_context * ctr_drbg_context);
		int randomWithAdd(State & state, mbedtls_ctr_drbg_context * ctr_drbg_context);
		int random(State & state, mbedtls_ctr_drbg_context * ctr_drbg_context);
		int writeSeedFile(State & state, mbedtls_ctr_drbg_context * ctr_drbg_context);
		int updateFromSeedFile(State & state, mbedtls_ctr_drbg_context * ctr_drbg_context);

	};
	void initCTRDRBGContext(State*, Module&);
};
#endif	
