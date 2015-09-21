#include "objects/x509crtProfile.hpp"

namespace luambedtls {
	mbedtls_x509_crt_profile * x509crtProfile::constructor(State & state, bool & managed){
		return nullptr;
	}

	void x509crtProfile::destructor(State & state, mbedtls_x509_crt_profile * object){
		delete object;
	}

	void initx509crtProfile(State * state, Module & module){
		INIT_OBJECT(x509crtProfile);
	}
};
