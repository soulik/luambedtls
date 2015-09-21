#include "objects/x509csr.hpp"

namespace luambedtls {
	mbedtls_x509_csr * x509csr::constructor(State & state, bool & managed){
		mbedtls_x509_csr * request = new mbedtls_x509_csr;
		mbedtls_x509_csr_init(request);
		return request;
	}

	void x509csr::destructor(State & state, mbedtls_x509_csr * request){
		mbedtls_x509_csr_free(request);
		delete request;
	}

	int x509csr::parse(State & state, mbedtls_x509_csr * request){
		Stack * stack = state.stack;
		if (stack->is<LUA_TSTRING>(1)){
			const std::string data = stack->toLString(1);
			stack->push<int>(mbedtls_x509_csr_parse(request, reinterpret_cast<const unsigned char*>(data.c_str()), data.length()));
			return 1;
		}
		return 0;
	}
	int x509csr::parseDER(State & state, mbedtls_x509_csr * request){
		Stack * stack = state.stack;
		if (stack->is<LUA_TSTRING>(1)){
			const std::string data = stack->toLString(1);
			stack->push<int>(mbedtls_x509_csr_parse_der(request, reinterpret_cast<const unsigned char*>(data.c_str()), data.length()));
			return 1;
		}
		return 0;
	}
	int x509csr::parseFile(State & state, mbedtls_x509_csr * request){
		Stack * stack = state.stack;
		if (stack->is<LUA_TSTRING>(1)){
			const std::string path = stack->to<const std::string>(1);
			stack->push<int>(mbedtls_x509_csr_parse_file(request, path.c_str()));
			return 1;
		}
		return 0;
	}
	int x509csr::info(State & state, mbedtls_x509_csr * request){
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
		int result = mbedtls_x509_csr_info(buffer, bufferSize, prefix.c_str(), request);
		if (result == 0){
			stack->push<const std::string &>(buffer);
		}
		else{
			stack->push<int>(result);
		}
		delete[] buffer;
		return 1;
	}

	void initx509csr(State * state, Module & module){
		INIT_OBJECT(x509csr);
	}
};
