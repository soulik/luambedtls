#ifndef LUA_MBEDTLS_OBJECTS_ASN1BUF_H
#define LUA_MBEDTLS_OBJECTS_ASN1BUF_H

#include "common.hpp"

namespace luambedtls {
	class ASN1buf : public Object<mbedtls_asn1_buf> {
	public:
		explicit ASN1buf(State * state) : Object<mbedtls_asn1_buf>(state){
			LUTOK_PROPERTY("len", &ASN1buf::getLen, &ASN1buf::nullMethod);
			LUTOK_PROPERTY("tag", &ASN1buf::getTag, &ASN1buf::nullMethod);
			LUTOK_PROPERTY("value", &ASN1buf::getValue, &ASN1buf::setValue);
		}

		mbedtls_asn1_buf * constructor(State & state, bool & managed);

		void destructor(State & state, mbedtls_asn1_buf * buffer);

		int getLen(State & state, mbedtls_asn1_buf * buffer);
		int getTag(State & state, mbedtls_asn1_buf * buffer);

		int getValue(State & state, mbedtls_asn1_buf * buffer);
		int setValue(State & state, mbedtls_asn1_buf * buffer);

		int operator_tostring(State & state, mbedtls_asn1_buf * buffer);

		void pushX509(mbedtls_x509_buf  * instance, const bool manage = false);
		void pushSequence(mbedtls_x509_sequence  * instance, const bool manage = false);
	};
};

#endif	
