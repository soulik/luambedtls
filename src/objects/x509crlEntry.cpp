#include "objects/x509crlEntry.hpp"
#include "objects/ASN1buf.hpp"
#include "objects/ASN1named.hpp"

namespace luambedtls {
	mbedtls_x509_crl_entry * x509crlEntry::constructor(State & state, bool & managed){
		mbedtls_x509_crl_entry * entry = new mbedtls_x509_crl_entry;
		return entry;
	}

	void x509crlEntry::destructor(State & state, mbedtls_x509_crl_entry * entry){
		delete entry;
	}

	int x509crlEntry::getRaw(State & state, mbedtls_x509_crl_entry * entry){
		Stack * stack = state.stack;
		ASN1buf * interfaceASN1buf = OBJECT_IFACE(ASN1buf);
		interfaceASN1buf->pushX509(&entry->raw);
		return 1;
	}
	int x509crlEntry::getSerial(State & state, mbedtls_x509_crl_entry * entry){
		Stack * stack = state.stack;
		ASN1buf * interfaceASN1buf = OBJECT_IFACE(ASN1buf);
		interfaceASN1buf->pushX509(&entry->serial);
		return 1;
	}
	int x509crlEntry::getRevocationDate(State & state, mbedtls_x509_crl_entry * entry){
		Stack * stack = state.stack;
		return pushX509time(state, &entry->revocation_date);
	}
	int x509crlEntry::getEntryExt(State & state, mbedtls_x509_crl_entry * entry){
		Stack * stack = state.stack;
		ASN1buf * interfaceASN1buf = OBJECT_IFACE(ASN1buf);
		interfaceASN1buf->pushX509(&entry->entry_ext);
		return 1;
	}
	int x509crlEntry::getNext(State & state, mbedtls_x509_crl_entry * entry){
		Stack * stack = state.stack;
		x509crlEntry * interfaceEntry = OBJECT_IFACE(x509crlEntry);
		if (entry->next){
			interfaceEntry->push(entry->next);
			return 1;
		}
		else{
			return 0;
		}
	}

	void initx509crlEntry(State * state, Module & module){
		INIT_OBJECT(x509crlEntry);
	}
};
