#include "objects/x509crl.hpp"
#include "objects/x509crlEntry.hpp"
#include "objects/ASN1buf.hpp"
#include "objects/ASN1named.hpp"
#include "objects/PKContext.hpp"

namespace luambedtls {
	mbedtls_x509_crl * x509crl::constructor(State & state, bool & managed){
		mbedtls_x509_crl * certificate = new mbedtls_x509_crl;
		mbedtls_x509_crl_init(certificate);
		return certificate;
	}

	void x509crl::destructor(State & state, mbedtls_x509_crl * certificate){
		mbedtls_x509_crl_free(certificate);
		delete certificate;
	}

	int x509crl::parse(State & state, mbedtls_x509_crl * certificate){
		Stack * stack = state.stack;
		if (stack->is<LUA_TSTRING>(1)){
			const std::string data = stack->toLString(1);
			stack->push<int>(mbedtls_x509_crl_parse(certificate, reinterpret_cast<const unsigned char*>(data.c_str()), data.length()));
			return 1;
		}
		return 0;
	}
	int x509crl::parseDER(State & state, mbedtls_x509_crl * certificate){
		Stack * stack = state.stack;
		if (stack->is<LUA_TSTRING>(1)){
			const std::string data = stack->toLString(1);
			stack->push<int>(mbedtls_x509_crl_parse_der(certificate, reinterpret_cast<const unsigned char*>(data.c_str()), data.length()));
			return 1;
		}
		return 0;
	}
	int x509crl::parseFile(State & state, mbedtls_x509_crl * certificate){
		Stack * stack = state.stack;
		if (stack->is<LUA_TSTRING>(1)){
			const std::string path = stack->to<const std::string>(1);
			stack->push<int>(mbedtls_x509_crl_parse_file(certificate, path.c_str()));
			return 1;
		}
		return 0;
	}
	int x509crl::info(State & state, mbedtls_x509_crl * certificate){
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
		int result = mbedtls_x509_crl_info(buffer, bufferSize, prefix.c_str(), certificate);
		if (result == 0){
			stack->push<const std::string &>(buffer);
		}
		else{
			stack->push<int>(result);
		}
		delete[] buffer;
		return 1;
	}

	int x509crl::getRaw(State & state, mbedtls_x509_crl * certificate){
		Stack * stack = state.stack;
		ASN1buf * interfaceASN1buf = OBJECT_IFACE(ASN1buf);
		interfaceASN1buf->pushX509(&certificate->raw);
		return 1;
	}
	int x509crl::getTBS(State & state, mbedtls_x509_crl * certificate){
		Stack * stack = state.stack;
		ASN1buf * interfaceASN1buf = OBJECT_IFACE(ASN1buf);
		interfaceASN1buf->pushX509(&certificate->tbs);
		return 1;
	}
	int x509crl::getVersion(State & state, mbedtls_x509_crl * certificate){
		Stack * stack = state.stack;
		stack->push<int>(certificate->version);
		return 1;
	}
	int x509crl::getSigOID(State & state, mbedtls_x509_crl * certificate){
		Stack * stack = state.stack;
		ASN1buf * interfaceASN1buf = OBJECT_IFACE(ASN1buf);
		interfaceASN1buf->pushX509(&certificate->sig_oid);
		return 1;
	}
	int x509crl::getIssuerRaw(State & state, mbedtls_x509_crl * certificate){
		Stack * stack = state.stack;
		ASN1buf * interfaceASN1buf = OBJECT_IFACE(ASN1buf);
		interfaceASN1buf->pushX509(&certificate->issuer_raw);
		return 1;
	}
	int x509crl::getIssuer(State & state, mbedtls_x509_crl * certificate){
		Stack * stack = state.stack;
		ASN1named * interfaceASN1named = OBJECT_IFACE(ASN1named);
		interfaceASN1named->push(&certificate->issuer);
		return 1;
	}
	int x509crl::getThisUpdate(State & state, mbedtls_x509_crl * certificate){
		Stack * stack = state.stack;
		return pushX509time(state, &certificate->this_update);
	}
	int x509crl::getNextUpdate(State & state, mbedtls_x509_crl * certificate){
		Stack * stack = state.stack;
		return pushX509time(state, &certificate->next_update);
	}
	int x509crl::getEntry(State & state, mbedtls_x509_crl * certificate){
		Stack * stack = state.stack;
		x509crlEntry * interfaceEntry = OBJECT_IFACE(x509crlEntry);
		interfaceEntry->push(&certificate->entry);
		return 1;
	}
	int x509crl::getCrlExt(State & state, mbedtls_x509_crl * certificate){
		Stack * stack = state.stack;
		ASN1buf * interfaceASN1buf = OBJECT_IFACE(ASN1buf);
		interfaceASN1buf->pushX509(&certificate->crl_ext);
		return 1;
	}
	int x509crl::getSigOID2(State & state, mbedtls_x509_crl * certificate){
		Stack * stack = state.stack;
		ASN1buf * interfaceASN1buf = OBJECT_IFACE(ASN1buf);
		interfaceASN1buf->pushX509(&certificate->sig_oid2);
		return 1;
	}
	int x509crl::getSig(State & state, mbedtls_x509_crl * certificate){
		Stack * stack = state.stack;
		ASN1buf * interfaceASN1buf = OBJECT_IFACE(ASN1buf);
		interfaceASN1buf->pushX509(&certificate->sig);
		return 1;
	}
	int x509crl::getSigMD(State & state, mbedtls_x509_crl * certificate){
		Stack * stack = state.stack;
		stack->push<LUA_NUMBER>(certificate->sig_md);
		return 1;
	}
	int x509crl::getSigPK(State & state, mbedtls_x509_crl * certificate){
		Stack * stack = state.stack;
		stack->push<LUA_NUMBER>(certificate->sig_md);
		return 1;
	}
	int x509crl::getNext(State & state, mbedtls_x509_crl * certificate){
		Stack * stack = state.stack;
		x509crl * interfaceCRL = OBJECT_IFACE(x509crl);
		if (certificate->next){
			interfaceCRL->push(certificate->next);
			return 1;
		}
		else{
			return 0;
		}
	}

	void initx509crl(State * state, Module & module){
		INIT_OBJECT(x509crl);
	}
};
