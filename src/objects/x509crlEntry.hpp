#ifndef LUA_MBEDTLS_OBJECTS_X509CRLENTRY_H
#define LUA_MBEDTLS_OBJECTS_X509CRLENTRY_H

#include "common.hpp"

namespace luambedtls {
	class x509crlEntry : public Object<mbedtls_x509_crl_entry> {
	public:
		explicit x509crlEntry(State * state) : Object<mbedtls_x509_crl_entry>(state){
			LUTOK_PROPERTY("raw", &x509crlEntry::getRaw, &x509crlEntry::nullMethod);
			LUTOK_PROPERTY("serial", &x509crlEntry::getRaw, &x509crlEntry::nullMethod);
			LUTOK_PROPERTY("revocationDate", &x509crlEntry::getRaw, &x509crlEntry::nullMethod);
			LUTOK_PROPERTY("entryExt", &x509crlEntry::getRaw, &x509crlEntry::nullMethod);
			LUTOK_PROPERTY("next", &x509crlEntry::getRaw, &x509crlEntry::nullMethod);
		}

		mbedtls_x509_crl_entry * constructor(State & state, bool & managed);

		void destructor(State & state, mbedtls_x509_crl_entry * entry);

		int getRaw(State & state, mbedtls_x509_crl_entry * entry);
		int getSerial(State & state, mbedtls_x509_crl_entry * entry);
		int getRevocationDate(State & state, mbedtls_x509_crl_entry * entry);
		int getEntryExt(State & state, mbedtls_x509_crl_entry * entry);
		int getNext(State & state, mbedtls_x509_crl_entry * entry);
	};
	void initx509crlEntry(State*, Module&);
};
#endif	
