#ifndef LUA_MBEDTLS_OBJECTS_ASN1NAMED_H
#define LUA_MBEDTLS_OBJECTS_ASN1NAMED_H

#include "common.hpp"

namespace luambedtls {
	class ASN1named : public Object<mbedtls_asn1_named_data> {
	public:
		explicit ASN1named(State * state) : Object<mbedtls_asn1_named_data>(state){
			LUTOK_PROPERTY("oid", &ASN1named::getOID, &ASN1named::nullMethod);
			LUTOK_PROPERTY("val", &ASN1named::getVal, &ASN1named::nullMethod);
			LUTOK_PROPERTY("next", &ASN1named::getNext, &ASN1named::nullMethod);
			LUTOK_PROPERTY("s", &ASN1named::getS, &ASN1named::nullMethod);
		}

		mbedtls_asn1_named_data * constructor(State & state, bool & managed);

		void destructor(State & state, mbedtls_asn1_named_data * object);

		int getOID(State & state, mbedtls_asn1_named_data * object);
		int getVal(State & state, mbedtls_asn1_named_data * object);
		int getNext(State & state, mbedtls_asn1_named_data * object);
		int getS(State & state, mbedtls_asn1_named_data * object);
	};
};

#endif	
