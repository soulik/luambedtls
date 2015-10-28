#include "objects/ASN1sequence.hpp"
#include "objects/ASN1buf.hpp"

namespace luambedtls {
	mbedtls_asn1_sequence * ASN1sequence::constructor(State & state, bool & managed){
		mbedtls_asn1_sequence * data = new mbedtls_asn1_sequence;
		data->next = nullptr;

		data->buf.len = 0;
		data->buf.p = nullptr;
		data->buf.tag = MBEDTLS_ASN1_NULL;

		return data;
	}

	void ASN1sequence::destructor(State & state, mbedtls_asn1_sequence * data){
		if (data->buf.len > 0 && data->buf.tag != MBEDTLS_ASN1_NULL){
			delete data->buf.p;
		}
		delete data;
	}

	int ASN1sequence::getNext(State & state, mbedtls_asn1_sequence * data){
		Stack * stack = state.stack;
		ASN1sequence * interfaceASN1sequence = OBJECT_IFACE(ASN1sequence);
		if (data->next){
			interfaceASN1sequence->push(data->next);
		}
		else{
			stack->pushNil();
		}
		return 1;
	}

	int ASN1sequence::getBuffer(State & state, mbedtls_asn1_sequence * data){
		Stack * stack = state.stack;
		ASN1buf * interfaceASN1buffer = OBJECT_IFACE(ASN1buf);
		interfaceASN1buffer->push(&data->buf);
		return 1;
	}

	void initASN1sequence(State * state, Module & module){
		INIT_OBJECT(ASN1sequence);
	}
};
