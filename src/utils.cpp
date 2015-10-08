#include "common.hpp"
#include "utils.hpp"
#include "objects/ASN1buf.hpp"

namespace luambedtls {
	int pushMPI(Stack * stack, const mbedtls_mpi * X, int radix){
		const size_t bufferLen = 2048;
		char buffer[bufferLen];
		size_t olen = 0;
		if (mbedtls_mpi_write_string(X, radix, buffer, bufferLen, &olen) == 0){
			stack->pushLString(std::string(buffer, olen));
			return 1;
		}
		return 0;
	}

	int readMPI(Stack * stack, mbedtls_mpi * X, int radix, const int index){
		if (stack->is<LUA_TSTRING>(index)){
			const std::string str = stack->to<const std::string>(index);
			if (mbedtls_mpi_read_string(X, radix, str.c_str()) == 0){
				return 1;
			}
		}
		return 0;
	}

	int MPIlen(State & state){
		Stack * stack = state.stack;
		mbedtls_mpi X;
		mbedtls_mpi_init(&X);
		if (stack->is<LUA_TSTRING>(1) && stack->is<LUA_TNUMBER>(2)){
			int radix = stack->to<int>(2);
			const std::string str = stack->to<const std::string>(1);
			if (mbedtls_mpi_read_string(&X, radix, str.c_str()) == 0){
				stack->push<LUA_NUMBER>(static_cast<LUA_NUMBER>(mbedtls_mpi_bitlen(&X)));
				return 1;
			}
		}
		return 0;
	}

	int pushX509time(State & state, mbedtls_x509_time * t){
		Stack * stack = state.stack;
		stack->newTable();
		{
			stack->setField<int>("day", t->day);
			stack->setField<int>("mon", t->mon);
			stack->setField<int>("year", t->year);
			stack->setField<int>("hour", t->hour);
			stack->setField<int>("min", t->min);
			stack->setField<int>("sec", t->sec);
		}
		return 1;
	}

	int pushOIDAttrShortName(State & state){
		Stack * stack = state.stack;
		ASN1buf * interfaceASN1buf = OBJECT_IFACE(ASN1buf);

		const mbedtls_asn1_buf * buf = interfaceASN1buf->get(1);
		if (buf){
			const char *short_name = NULL;
			int result = mbedtls_oid_get_attr_short_name(buf, &short_name);
			if (result == 0){
				stack->push<const std::string &>(short_name);
			}
			else{
				stack->push<int>(result);
			}
			return 1;
		}
		else{
			return 0;
		}
	}

	int pushOIDNumericString(State & state){
		Stack * stack = state.stack;
		ASN1buf * interfaceASN1buf = OBJECT_IFACE(ASN1buf);

		const mbedtls_asn1_buf * buf = interfaceASN1buf->get(1);
		if (buf){
			const size_t buffersize = 128;
			char buffer[buffersize];
			int result = mbedtls_oid_get_numeric_string(buffer, buffersize, buf);
			if (result == 0){
				stack->push<const std::string &>(buffer);
			}
			else{
				stack->push<int>(result);
			}
			return 1;
		}
		else{
			return 0;
		}
	}
	int pushOIDExtType(State & state){
		Stack * stack = state.stack;
		ASN1buf * interfaceASN1buf = OBJECT_IFACE(ASN1buf);

		const mbedtls_asn1_buf * buf = interfaceASN1buf->get(1);
		if (buf){
			int extType;
			mbedtls_oid_get_x509_ext_type(buf, &extType);
			stack->push<int>(extType);
			return 1;
		}
		else{
			return 0;
		}
	}

	int pushOIDPkAlg(State & state){
		Stack * stack = state.stack;
		ASN1buf * interfaceASN1buf = OBJECT_IFACE(ASN1buf);

		const mbedtls_asn1_buf * buf = interfaceASN1buf->get(1);
		if (buf){
			mbedtls_pk_type_t extType;
			mbedtls_oid_get_pk_alg(buf, &extType);
			stack->push<int>(extType);
			return 1;
		}
		else{
			return 0;
		}
	}

	int base64Encode(State & state){
		Stack * stack = state.stack;
		if (stack->is<LUA_TSTRING>(1)){
			const std::string input = stack->toLString(1);
			/*
				Output length approximation
				source: http://stackoverflow.com/questions/1533113/calculate-the-size-to-a-base-64-encoded-message
			*/
			const size_t inputLength = input.length();
			const size_t outputMaxLength = ((inputLength * 4) / 3) + (inputLength / 96) + 6;
			size_t outputLength = 0;
			unsigned char * output = new unsigned char[outputMaxLength];
			int result = mbedtls_base64_encode(output, outputMaxLength, &outputLength, reinterpret_cast<const unsigned char *>(input.c_str()), inputLength);
			if (result == 0){
				stack->pushLString(std::string(reinterpret_cast<char*>(output), outputLength));
			}
			else{
				stack->push<int>(result);
			}
			delete[] output;
			return 1;
		}
		return 0;
	}

	int base64Decode(State & state){
		Stack * stack = state.stack;
		if (stack->is<LUA_TSTRING>(1)){
			const std::string input = stack->toLString(1);
			const size_t inputLength = input.length();
			const size_t outputMaxLength = inputLength;
			size_t outputLength = 0;
			unsigned char * output = new unsigned char[outputMaxLength];
			int result = mbedtls_base64_decode(output, outputMaxLength, &outputLength, reinterpret_cast<const unsigned char *>(input.c_str()), inputLength);
			if (result == 0){
				stack->pushLString(std::string(reinterpret_cast<char*>(output), outputLength));
			}
			else{
				stack->push<int>(result);
			}
			delete[] output;
			return 1;
		}
		return 0;
	}

	int base64SelfTest(State & state){
		Stack * stack = state.stack;
		stack->push<int>(mbedtls_base64_self_test(stack->to<int>(1)));
		return 1;
	}

	void initUtils(State * state, Module & module){
		module["base64Encode"] = base64Encode;
		module["base64Decode"] = base64Decode;
		module["base64SelfTest"] = base64SelfTest;
	}

};
