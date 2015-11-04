#ifndef LUA_MBEDTLS_OBJECTS_ASN1SEQUENCE_H
#define LUA_MBEDTLS_OBJECTS_ASN1SEQUENCE_H

#include "common.hpp"

namespace luambedtls {
	class ASN1sequence : public Object<mbedtls_asn1_sequence> {
	public:
		explicit ASN1sequence(State * state) : Object<mbedtls_asn1_sequence>(state){
			LUTOK_PROPERTY("next", &ASN1sequence::getNext, &ASN1sequence::nullMethod);
			LUTOK_PROPERTY("buf", &ASN1sequence::getBuffer, &ASN1sequence::nullMethod);
		}

		mbedtls_asn1_sequence * constructor(State & state, bool & managed);

		void destructor(State & state, mbedtls_asn1_sequence * data);

		int getNext(State & state, mbedtls_asn1_sequence * data);
		int getBuffer(State & state, mbedtls_asn1_sequence * data);
	};
};

#endif	
