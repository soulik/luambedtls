#include "objects/CTRDRBGContext.hpp"
#include "objects/EntropyContext.hpp"

namespace luambedtls {
	mbedtls_ctr_drbg_context * CTRDRBGContext::constructor(State & state, bool & managed){
		mbedtls_ctr_drbg_context * ctr_drbg_context = new mbedtls_ctr_drbg_context;
		mbedtls_ctr_drbg_init(ctr_drbg_context);
		return ctr_drbg_context;
	}

	void CTRDRBGContext::destructor(State & state, mbedtls_ctr_drbg_context * ctr_drbg_context){
		mbedtls_ctr_drbg_free(ctr_drbg_context);
		delete ctr_drbg_context;
	}

	int CTRDRBGContext::seed(State & state, mbedtls_ctr_drbg_context * ctr_drbg_context){
		Stack * stack = state.stack;
		EntropyContext * interfaceEntropyContext = OBJECT_IFACE(EntropyContext);

		mbedtls_entropy_context * entropy = interfaceEntropyContext->get(1);

		if (entropy){
			unsigned char * persData = nullptr;
			size_t persDataLen = 0;
			if (stack->is<LUA_TSTRING>(2)){
				const std::string persDataStr = stack->toLString(2);
				persData = reinterpret_cast<unsigned char *>(const_cast<char *>(persDataStr.c_str()));
				persDataLen = persDataStr.length();
			}

			stack->push<int>(mbedtls_ctr_drbg_seed(ctr_drbg_context, mbedtls_entropy_func, entropy, persData, persDataLen));
			return 1;
		}
		return 0;
	}

	int CTRDRBGContext::setPredictionResistance(State & state, mbedtls_ctr_drbg_context * ctr_drbg_context){
		Stack * stack = state.stack;
		mbedtls_ctr_drbg_set_prediction_resistance(ctr_drbg_context, stack->to<int>(1));
		return 0;
	}

	int CTRDRBGContext::setLength(State & state, mbedtls_ctr_drbg_context * ctr_drbg_context){
		Stack * stack = state.stack;
		mbedtls_ctr_drbg_set_entropy_len(ctr_drbg_context, stack->to<int>(1));
		return 0;
	}

	int CTRDRBGContext::setReseedInterval(State & state, mbedtls_ctr_drbg_context * ctr_drbg_context){
		Stack * stack = state.stack;
		mbedtls_ctr_drbg_set_reseed_interval(ctr_drbg_context, stack->to<int>(1));
		return 0;
	}

	int CTRDRBGContext::reseed(State & state, mbedtls_ctr_drbg_context * ctr_drbg_context){
		Stack * stack = state.stack;
		if (stack->is<LUA_TSTRING>(1)){
			const std::string seed = stack->toLString(1);
			mbedtls_ctr_drbg_reseed(ctr_drbg_context, reinterpret_cast<unsigned char *>(const_cast<char *>(seed.c_str())), seed.length());
		}
		return 0;
	}

	int CTRDRBGContext::update(State & state, mbedtls_ctr_drbg_context * ctr_drbg_context){
		Stack * stack = state.stack;
		if (stack->is<LUA_TSTRING>(1)){
			const std::string seed = stack->toLString(1);
			mbedtls_ctr_drbg_update(ctr_drbg_context, reinterpret_cast<unsigned char *>(const_cast<char *>(seed.c_str())), seed.length());
		}
		return 0;
	}

	int CTRDRBGContext::randomWithAdd(State & state, mbedtls_ctr_drbg_context * ctr_drbg_context){
		Stack * stack = state.stack;

		size_t length = stack->to<int>(1);
		unsigned char * buffer = new unsigned char[length];

		unsigned char * seed = nullptr;
		size_t seedLen = 0;


		if (stack->is<LUA_TSTRING>(2)){
			const std::string seedStr = stack->toLString(2);
			seed = reinterpret_cast<unsigned char *>(const_cast<char *>(seedStr.c_str()));
			seedLen = seedStr.length();
		}

		if (mbedtls_ctr_drbg_random_with_add(ctr_drbg_context, buffer, length, seed, seedLen) == 0){
			stack->pushLString(std::string(reinterpret_cast<char*>(buffer), length));
			delete[] buffer;
		}
		else{
			delete[] buffer;
		}
		return 0;
	}

	int CTRDRBGContext::random(State & state, mbedtls_ctr_drbg_context * ctr_drbg_context){
		Stack * stack = state.stack;

		size_t length = stack->to<int>(1);
		unsigned char * buffer = new unsigned char[length];

		int result = mbedtls_ctr_drbg_random(ctr_drbg_context, buffer, length);
		if (result == 0){
			stack->pushLString(std::string(reinterpret_cast<char*>(buffer), length));
			delete[] buffer;
			return 1;
		}
		else{
			stack->push<int>(result);
			delete[] buffer;
			return 1;
		}
		return 0;
	}

	int CTRDRBGContext::writeSeedFile(State & state, mbedtls_ctr_drbg_context * ctr_drbg_context){
		Stack * stack = state.stack;
		if (stack->is<LUA_TSTRING>(1)){
			const std::string fileName = stack->to<const std::string>(1);
			stack->push<int>(mbedtls_ctr_drbg_write_seed_file(ctr_drbg_context, fileName.c_str()));
			return 1;
		}
		return 0;
	}

	int CTRDRBGContext::updateFromSeedFile(State & state, mbedtls_ctr_drbg_context * ctr_drbg_context){
		Stack * stack = state.stack;
		if (stack->is<LUA_TSTRING>(1)){
			const std::string fileName = stack->to<const std::string>(1);
			stack->push<int>(mbedtls_ctr_drbg_update_seed_file(ctr_drbg_context, fileName.c_str()));
			return 1;
		}
		return 0;
	}

	static int CTRDRBGSelfTest(State & state){
		Stack * stack = state.stack;
		
		stack->push<int>(mbedtls_ctr_drbg_self_test(stack->to<int>(1)));
		return 1;
	}

	void initCTRDRBGContext(State * state, Module & module){
		INIT_OBJECT(CTRDRBGContext);
		module["CTRDRBGSelfTest"] = CTRDRBGSelfTest;
	}
};
