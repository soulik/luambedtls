#include "objects/x509crtProfile.hpp"

namespace luambedtls {
	mbedtls_x509_crt_profile * x509crtProfile::constructor(State & state, bool & managed){
		mbedtls_x509_crt_profile * profile = new mbedtls_x509_crt_profile;
		return profile;
	}

	void x509crtProfile::destructor(State & state, mbedtls_x509_crt_profile * profile){
		delete profile;
	}

	int x509crtProfile::getAllowedMDs(State & state, mbedtls_x509_crt_profile * profile){
		Stack * stack = state.stack;
		stack->push<LUA_NUMBER>(profile->allowed_mds);
		return 1;
	}
	int x509crtProfile::getAllowedPKs(State & state, mbedtls_x509_crt_profile * profile){
		Stack * stack = state.stack;
		stack->push<LUA_NUMBER>(profile->allowed_pks);
		return 1;
	}
	int x509crtProfile::getAllowedCurves(State & state, mbedtls_x509_crt_profile * profile){
		Stack * stack = state.stack;
		stack->push<LUA_NUMBER>(profile->allowed_curves);
		return 1;
	}
	int x509crtProfile::getRSAMinBitlen(State & state, mbedtls_x509_crt_profile * profile){
		Stack * stack = state.stack;
		stack->push<LUA_NUMBER>(profile->rsa_min_bitlen);
		return 1;
	}

	void initx509crtProfile(State * state, Module & module){
		INIT_OBJECT(x509crtProfile);
	}
};
