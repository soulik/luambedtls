#ifndef LUA_MBEDTLS_OBJECTS_X509CSR_H
#define LUA_MBEDTLS_OBJECTS_X509CSR_H

#include "common.hpp"

namespace luambedtls {
	class x509csr : public Object<mbedtls_x509_csr> {
	public:
		explicit x509csr(State * state) : Object<mbedtls_x509_csr>(state){
			LUTOK_METHOD("parse", &x509csr::parse);
			LUTOK_METHOD("parseDER", &x509csr::parseDER);
			LUTOK_METHOD("parseFile", &x509csr::parseFile);
			LUTOK_METHOD("info", &x509csr::info);

			LUTOK_PROPERTY("raw", &x509csr::getRaw, &x509csr::nullMethod);
			LUTOK_PROPERTY("CRI", &x509csr::getCRI, &x509csr::nullMethod);
			LUTOK_PROPERTY("version", &x509csr::getVersion, &x509csr::nullMethod);
			LUTOK_PROPERTY("subject", &x509csr::getSubject, &x509csr::nullMethod);
			LUTOK_PROPERTY("subjectRaw", &x509csr::getSubjectRaw, &x509csr::nullMethod);
			LUTOK_PROPERTY("pk", &x509csr::getPK, &x509csr::nullMethod);
			LUTOK_PROPERTY("sigOID", &x509csr::getSigOID, &x509csr::nullMethod);
			LUTOK_PROPERTY("sig", &x509csr::getSig, &x509csr::nullMethod);
			LUTOK_PROPERTY("sigMD", &x509csr::getSigMD, &x509csr::nullMethod);
			LUTOK_PROPERTY("sigPK", &x509csr::getSigPK, &x509csr::nullMethod);
		}

		mbedtls_x509_csr * constructor(State & state, bool & managed);

		void destructor(State & state, mbedtls_x509_csr * request);

		int parse(State & state, mbedtls_x509_csr * request);
		int parseDER(State & state, mbedtls_x509_csr * request);
		int parseFile(State & state, mbedtls_x509_csr * request);
		int info(State & state, mbedtls_x509_csr * request);

		int getRaw(State & state, mbedtls_x509_csr * request);
		int getCRI(State & state, mbedtls_x509_csr * request);
		int getVersion(State & state, mbedtls_x509_csr * request);
		int getSubject(State & state, mbedtls_x509_csr * request);
		int getSubjectRaw(State & state, mbedtls_x509_csr * request);
		int getPK(State & state, mbedtls_x509_csr * request);
		int getSigOID(State & state, mbedtls_x509_csr * request);
		int getSig(State & state, mbedtls_x509_csr * request);
		int getSigMD(State & state, mbedtls_x509_csr * request);
		int getSigPK(State & state, mbedtls_x509_csr * request);
	};
	void initx509csr(State*, Module&);
};
#endif	
