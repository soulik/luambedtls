#include "objects/x509crl.hpp"

namespace luambedtls {
	mbedtls_x509_crl * x509crl::constructor(State & state, bool & managed){
		mbedtls_x509_crl * certificate = new mbedtls_x509_crl;
		mbedtls_x509_crl_init(certificate);
		return certificate;
	}

	void x509crl::destructor(State & state, mbedtls_x509_crl * certificate){
		mbedtls_x509_crl_free(certificate);
		delete certificate;
	}

	int x509crl::parse(State & state, mbedtls_x509_crl * certificate){
		Stack * stack = state.stack;
		if (stack->is<LUA_TSTRING>(1)){
			const std::string data = stack->toLString(1);
			stack->push<int>(mbedtls_x509_crl_parse(certificate, reinterpret_cast<const unsigned char*>(data.c_str()), data.length()));
			return 1;
		}
		return 0;
	}
	int x509crl::parseDER(State & state, mbedtls_x509_crl * certificate){
		Stack * stack = state.stack;
		if (stack->is<LUA_TSTRING>(1)){
			const std::string data = stack->toLString(1);
			stack->push<int>(mbedtls_x509_crl_parse_der(certificate, reinterpret_cast<const unsigned char*>(data.c_str()), data.length()));
			return 1;
		}
		return 0;
	}
	int x509crl::parseFile(State & state, mbedtls_x509_crl * certificate){
		Stack * stack = state.stack;
		if (stack->is<LUA_TSTRING>(1)){
			const std::string path = stack->to<const std::string>(1);
			stack->push<int>(mbedtls_x509_crl_parse_file(certificate, path.c_str()));
			return 1;
		}
		return 0;
	}
	int x509crl::info(State & state, mbedtls_x509_crl * certificate){
		Stack * stack = state.stack;
		std::string prefix = "";
		size_t bufferSize = 4096;
		if (stack->is<LUA_TNUMBER>(1)){
			bufferSize = stack->to<int>(1);
		}
		if (stack->is<LUA_TSTRING>(2)){
			prefix = stack->to<const std::string>(2);
		}
		char * buffer = new char[bufferSize];
		int result = mbedtls_x509_crl_info(buffer, bufferSize, prefix.c_str(), certificate);
		if (result == 0){
			stack->push<const std::string &>(buffer);
		}
		else{
			stack->push<int>(result);
		}
		delete[] buffer;
		return 1;
	}

	void initx509crl(State * state, Module & module){
		INIT_OBJECT(x509crl);
	}
};
