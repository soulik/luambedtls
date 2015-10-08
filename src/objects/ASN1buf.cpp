#include "objects/ASN1buf.hpp"

namespace luambedtls {
	mbedtls_asn1_buf * ASN1buf::constructor(State & state, bool & managed){
		mbedtls_asn1_buf * buffer = new mbedtls_asn1_buf;
		buffer->len = 0;
		buffer->p = nullptr;
		buffer->tag = MBEDTLS_ASN1_NULL;
		return buffer;
	}

	void ASN1buf::destructor(State & state, mbedtls_asn1_buf * buffer){
		if (buffer->len > 0 && buffer->tag != MBEDTLS_ASN1_NULL){
			delete buffer->p;
		}
		delete buffer;
	}

	int ASN1buf::getLen(State & state, mbedtls_asn1_buf * buffer){
		Stack * stack = state.stack;
		stack->push<int>(buffer->len);
		return 1;
	}
	int ASN1buf::getTag(State & state, mbedtls_asn1_buf * buffer){
		Stack * stack = state.stack;
		stack->push<int>(buffer->tag);
		return 1;
	}

	int ASN1buf::getValue(State & state, mbedtls_asn1_buf * buffer){
		ASN1buf * interfaceASN1buf = OBJECT_IFACE(ASN1buf);

		Stack * stack = state.stack;
		mbedtls_asn1_bitstring * bitstring = nullptr;
		mbedtls_asn1_sequence * sequence = nullptr;
		mbedtls_asn1_named_data * name = nullptr;
		size_t workLen = buffer->len;
		int outputLen = 0;

		const size_t bufferSize = 4096;
		//char strBuffer[bufferSize];

		switch (buffer->tag){
		case MBEDTLS_ASN1_BOOLEAN:
			stack->push<bool>(reinterpret_cast<bool>(buffer->p));
			break;
		case MBEDTLS_ASN1_INTEGER:
			workLen = (workLen <= 32) ? workLen : 28;
			if (workLen <= 4){
				stack->push<int>(reinterpret_cast<int>(buffer->p));
			}
			else{
				stack->newTable();
				{
					for (size_t i = 0; i < workLen; i++){
						stack->push<int>(i+1);
						stack->push<int>(buffer->p[i]);
						stack->setTable(-3);
					}
				}
			}
			break;
		case MBEDTLS_ASN1_OID:
			name = reinterpret_cast<mbedtls_asn1_named_data*>(buffer);
			//outputLen = mbedtls_x509_dn_gets(strBuffer, bufferSize, name);
			//stack->pushLString(std::string(strBuffer, outputLen));
			stack->pushLString(std::string(reinterpret_cast<char *>(buffer->p), buffer->len));
			break;
		case MBEDTLS_ASN1_BIT_STRING:
			bitstring = reinterpret_cast<mbedtls_asn1_bitstring*>(buffer);
			stack->pushLString(std::string(reinterpret_cast<char *>(bitstring->p), bitstring->len));
			break;
		case MBEDTLS_ASN1_UTF8_STRING:
		case MBEDTLS_ASN1_PRINTABLE_STRING:
		case MBEDTLS_ASN1_OCTET_STRING:
		case MBEDTLS_ASN1_T61_STRING:
		case MBEDTLS_ASN1_IA5_STRING:
		case MBEDTLS_ASN1_BMP_STRING:
		case MBEDTLS_ASN1_UNIVERSAL_STRING:
		case MBEDTLS_ASN1_UTC_TIME:
		case MBEDTLS_ASN1_GENERALIZED_TIME:
			stack->pushLString(std::string(reinterpret_cast<char *>(buffer->p), buffer->len));
			break;
		case MBEDTLS_ASN1_NULL:
			stack->pushNil();
			break;
		case MBEDTLS_ASN1_SEQUENCE:
			sequence = reinterpret_cast<mbedtls_asn1_sequence*>(buffer);
			stack->newTable();
			{
				stack->push<const std::string &>("item");
				interfaceASN1buf->push(&sequence->buf);
				stack->setTable(-3);
				stack->push<const std::string &>("next");
				if (sequence->next != nullptr){
					interfaceASN1buf->push(reinterpret_cast<mbedtls_asn1_buf *>(sequence->next));
				}
				else{
					stack->pushNil();
				}
				stack->setTable(-3);
			}
		default:
			stack->newTable();
			{
				stack->push<const std::string &>("p");
				stack->push<void*>(buffer->p);
				stack->setTable(-3);
				stack->push<const std::string &>("len");
				stack->push<int>(buffer->len);
				stack->setTable(-3);
			}
		}
		return 1;
	}

	int ASN1buf::operator_tostring(State & state, mbedtls_asn1_buf * buffer){
		return getValue(state, buffer);
	}

	int ASN1buf::setValue(State & state, mbedtls_asn1_buf * buffer){
		Stack * stack = state.stack;
		return 0;
	}

	void ASN1buf::pushX509(mbedtls_x509_buf  * instance, const bool manage){
		push(static_cast<mbedtls_asn1_buf*>(instance), manage);
	}

	void ASN1buf::pushSequence(mbedtls_x509_sequence  * instance, const bool manage){
		//push(static_cast<mbedtls_asn1_buf*>(instance), manage);
	}

	void initASN1buf(State * state, Module & module){
		INIT_OBJECT(ASN1buf);
	}
};
