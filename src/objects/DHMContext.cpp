#include "objects/DHMContext.hpp"
#include "objects/CTRDRBGContext.hpp"
#include "objects/MPI.hpp"

namespace luambedtls {
#define PUSH_MPI(VALUE) Stack * stack = state.stack; MPI * interfaceMPI = OBJECT_IFACE(MPI); interfaceMPI->push(&context->VALUE); return 1
#define READ_MPI(VALUE) Stack * stack = state.stack; MPI * interfaceMPI = OBJECT_IFACE(MPI); mbedtls_mpi * value = interfaceMPI->get(1); if (value) mbedtls_mpi_copy(&context->VALUE, value); return 0

	mbedtls_dhm_context * DHMContext::constructor(State & state, bool & managed){
		mbedtls_dhm_context * context = new mbedtls_dhm_context;
		mbedtls_dhm_init(context);
		return context;
	}

	void DHMContext::destructor(State & state, mbedtls_dhm_context * context){
		mbedtls_dhm_free(context);
		delete context;
	}

	int DHMContext::readParams(State & state, mbedtls_dhm_context * context){
		Stack * stack = state.stack;
		if (stack->is<LUA_TSTRING>(1)){
			std::string str = stack->toLString(1);
			const unsigned char * origP = reinterpret_cast<const unsigned char*>(str.c_str());
			unsigned char * p = const_cast<unsigned char *>(origP);
			const unsigned char * end = p + str.length();
			int result = mbedtls_dhm_read_params(context, &p, end);
			if (result == 0){
				stack->push<bool>(true);
				stack->push<int>(p - origP);
			}
			else{
				stack->push<bool>(false);
				stack->push<int>(result);
			}
			return 2;
		}
		return 0;
	}
	int DHMContext::makeParams(State & state, mbedtls_dhm_context * context){
		Stack * stack = state.stack;
		CTRDRBGContext * interfaceCTRDRBGContext = OBJECT_IFACE(CTRDRBGContext);
		mbedtls_ctr_drbg_context * drbg = interfaceCTRDRBGContext->get(1);
		if (drbg){
			unsigned char buffer[2048];
			size_t n = 0;
			int result = mbedtls_dhm_make_params(context, static_cast<int>(mbedtls_mpi_size(&context->P)), buffer, &n, mbedtls_ctr_drbg_random, drbg);
			if (result == 0){
				stack->pushLString(std::string(reinterpret_cast<char*>(buffer), n));
			}
			else{
				stack->push<bool>(false);
			}
			return 1;
		}
		return 0;
	}
	int DHMContext::readPublic(State & state, mbedtls_dhm_context * context){
		Stack * stack = state.stack;
		if (stack->is<LUA_TSTRING>(1)){
			std::string str = stack->toLString(1);
			const unsigned char * input = reinterpret_cast<const unsigned char*>(str.c_str());
			stack->push<int>(mbedtls_dhm_read_public(context, input, str.length()));
			return 1;
		}
		return 0;
	}
	int DHMContext::makePublic(State & state, mbedtls_dhm_context * context){
		Stack * stack = state.stack;
		CTRDRBGContext * interfaceCTRDRBGContext = OBJECT_IFACE(CTRDRBGContext);
		mbedtls_ctr_drbg_context * drbg = interfaceCTRDRBGContext->get(1);
		if (stack->is<LUA_TNUMBER>(2) && drbg){
			unsigned char buffer[2048];
			size_t n = static_cast<size_t>(stack->to<int>(2));
			int result = mbedtls_dhm_make_public(context, context->len, buffer, n, mbedtls_ctr_drbg_random, drbg);
			if (result == 0){
				stack->pushLString(std::string(reinterpret_cast<char*>(buffer), n));
			}
			else{
				stack->push<bool>(false);
			}
			return 1;
		}
		return 0;
	}
	int DHMContext::calcSecret(State & state, mbedtls_dhm_context * context){
		Stack * stack = state.stack;
		CTRDRBGContext * interfaceCTRDRBGContext = OBJECT_IFACE(CTRDRBGContext);
		mbedtls_ctr_drbg_context * drbg = interfaceCTRDRBGContext->get(1);
		if (stack->is<LUA_TNUMBER>(2) && drbg){
			size_t n = static_cast<size_t>(stack->to<int>(2));
			unsigned char * buffer = new unsigned char[n];
			size_t olen = 0;

			int result = mbedtls_dhm_calc_secret(context, buffer, n, &olen, mbedtls_ctr_drbg_random, drbg);
			if (result == 0){
				stack->push<bool>(true);
				stack->pushLString(std::string(reinterpret_cast<char*>(buffer), olen));
			}
			else{
				stack->push<bool>(false);
				stack->push<int>(result);
			}
			delete[] buffer;
			return 2;
		}
		return 0;
	}
	int DHMContext::parseDHM(State & state, mbedtls_dhm_context * context){
		Stack * stack = state.stack;
		if (stack->is<LUA_TSTRING>(1)){
			std::string str = stack->toLString(1);
			const unsigned char * input = reinterpret_cast<const unsigned char*>(str.c_str());
			stack->push<int>(mbedtls_dhm_parse_dhm(context, input, str.length()));
			return 1;
		}
		return 0;
	}
	int DHMContext::parseDHMFile(State & state, mbedtls_dhm_context * context){
		Stack * stack = state.stack;
		if (stack->is<LUA_TSTRING>(1)){
			const std::string str = stack->to<const std::string>(1);
			stack->push<int>(mbedtls_dhm_parse_dhmfile(context, str.c_str()));
			return 1;
		}
		return 0;
	}

	int DHMContext::getLen(State & state, mbedtls_dhm_context * context){
		Stack * stack = state.stack;
		stack->push<LUA_NUMBER>(context->len);
		return 1;
	}
	int DHMContext::setLen(State & state, mbedtls_dhm_context * context){
		Stack * stack = state.stack;
		context->len = static_cast<size_t>(stack->to<LUA_NUMBER>(1));
		return 0;
	}
	int DHMContext::getP(State & state, mbedtls_dhm_context * context){
		PUSH_MPI(P);
	}
	int DHMContext::setP(State & state, mbedtls_dhm_context * context){
		READ_MPI(P);
	}
	int DHMContext::getG(State & state, mbedtls_dhm_context * context){
		PUSH_MPI(G);
	}
	int DHMContext::setG(State & state, mbedtls_dhm_context * context){
		READ_MPI(G);
	}
	int DHMContext::getX(State & state, mbedtls_dhm_context * context){
		PUSH_MPI(X);
	}
	int DHMContext::setX(State & state, mbedtls_dhm_context * context){
		READ_MPI(X);
	}
	int DHMContext::getGX(State & state, mbedtls_dhm_context * context){
		PUSH_MPI(GX);
	}
	int DHMContext::setGX(State & state, mbedtls_dhm_context * context){
		READ_MPI(GX);
	}
	int DHMContext::getGY(State & state, mbedtls_dhm_context * context){
		PUSH_MPI(GY);
	}
	int DHMContext::setGY(State & state, mbedtls_dhm_context * context){
		READ_MPI(GY);
	}
	int DHMContext::getK(State & state, mbedtls_dhm_context * context){
		PUSH_MPI(K);
	}
	int DHMContext::setK(State & state, mbedtls_dhm_context * context){
		READ_MPI(K);
	}
	int DHMContext::getRP(State & state, mbedtls_dhm_context * context){
		PUSH_MPI(RP);
	}
	int DHMContext::setRP(State & state, mbedtls_dhm_context * context){
		READ_MPI(RP);
	}
	int DHMContext::getVi(State & state, mbedtls_dhm_context * context){
		PUSH_MPI(Vi);
	}
	int DHMContext::setVi(State & state, mbedtls_dhm_context * context){
		READ_MPI(Vi);
	}
	int DHMContext::getVf(State & state, mbedtls_dhm_context * context){
		PUSH_MPI(Vf);
	}
	int DHMContext::setVf(State & state, mbedtls_dhm_context * context){
		READ_MPI(Vf);
	}
	int DHMContext::getpX(State & state, mbedtls_dhm_context * context){
		PUSH_MPI(pX);
	}
	int DHMContext::setpX(State & state, mbedtls_dhm_context * context){
		READ_MPI(pX);
	}

	int DHMSelfTest(State & state){
		Stack * stack = state.stack;
		stack->push<int>(mbedtls_dhm_self_test(stack->to<int>(1)));
		return 1;
	}

	void initDHMContext(State * state, Module & module){
		INIT_OBJECT(DHMContext);
		module["DHMSelfTest"] = DHMSelfTest;
	}
};
