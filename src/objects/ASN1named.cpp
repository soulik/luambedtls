#include "objects/ASN1named.hpp"
#include "objects/ASN1buf.hpp"

namespace luambedtls {
	mbedtls_asn1_named_data * ASN1named::constructor(State & state, bool & managed){
		mbedtls_asn1_named_data * data = new mbedtls_asn1_named_data;
		data->next = nullptr;

		data->oid.len = 0;
		data->oid.p = nullptr;
		data->oid.tag = MBEDTLS_ASN1_NULL;

		data->val.len = 0;
		data->val.p = nullptr;
		data->val.tag = MBEDTLS_ASN1_NULL;
		return data;
	}

	void ASN1named::destructor(State & state, mbedtls_asn1_named_data * data){
		mbedtls_asn1_free_named_data(data);
		delete data;
	}

	int ASN1named::getOID(State & state, mbedtls_asn1_named_data * data){
		Stack * stack = state.stack;
		ASN1buf * interfaceASN1buf = OBJECT_IFACE(ASN1buf);
		interfaceASN1buf->pushX509(&data->oid);
		return 1;
	}
	int ASN1named::getVal(State & state, mbedtls_asn1_named_data * data){
		Stack * stack = state.stack;
		ASN1buf * interfaceASN1buf = OBJECT_IFACE(ASN1buf);
		interfaceASN1buf->pushX509(&data->val);
		return 1;
	}
	int ASN1named::getNext(State & state, mbedtls_asn1_named_data * data){
		Stack * stack = state.stack;
		ASN1named * interfaceASN1named = OBJECT_IFACE(ASN1named);
		if (data->next){
			interfaceASN1named->push(data->next);
		}
		else{
			stack->pushNil();
		}
		return 1;
	}
	int ASN1named::getS(State & state, mbedtls_asn1_named_data * object){
		Stack * stack = state.stack;
		const size_t bufferSize = 1024;
		char buffer[bufferSize];
		int result = mbedtls_x509_dn_gets(buffer, bufferSize, object);
		if (result >= 0){
			stack->pushLString(std::string(buffer, result));
		}
		else{
			stack->push<int>(result);
		}
		return 1;
	}

	void initASN1named(State * state, Module & module){
		INIT_OBJECT(ASN1named);
	}
};
