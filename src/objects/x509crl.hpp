#ifndef LUA_MBEDTLS_OBJECTS_X509CRL_H
#define LUA_MBEDTLS_OBJECTS_X509CRL_H

#include "common.hpp"

namespace luambedtls {
	class x509crl : public Object<mbedtls_x509_crl> {
	public:
		explicit x509crl(State * state) : Object<mbedtls_x509_crl>(state){
			LUTOK_METHOD("parse", &x509crl::parse);
			LUTOK_METHOD("parseDER", &x509crl::parseDER);
			LUTOK_METHOD("parseFile", &x509crl::parseFile);
			LUTOK_METHOD("info", &x509crl::info);

			LUTOK_PROPERTY("raw", &x509crl::getRaw, &x509crl::nullMethod);
			LUTOK_PROPERTY("TBS", &x509crl::getTBS, &x509crl::nullMethod);
			LUTOK_PROPERTY("version", &x509crl::getVersion, &x509crl::nullMethod);
			LUTOK_PROPERTY("sigOID", &x509crl::getSigOID, &x509crl::nullMethod);
			LUTOK_PROPERTY("issuerRaw", &x509crl::getIssuerRaw, &x509crl::nullMethod);
			LUTOK_PROPERTY("issuer", &x509crl::getIssuer, &x509crl::nullMethod);
			LUTOK_PROPERTY("thisUpdate", &x509crl::getThisUpdate, &x509crl::nullMethod);
			LUTOK_PROPERTY("nextUpdate", &x509crl::getNextUpdate, &x509crl::nullMethod);
			LUTOK_PROPERTY("entry", &x509crl::getEntry, &x509crl::nullMethod);
			LUTOK_PROPERTY("crlExt", &x509crl::getCrlExt, &x509crl::nullMethod);
			LUTOK_PROPERTY("sigOID2", &x509crl::getSigOID2, &x509crl::nullMethod);
			LUTOK_PROPERTY("sig", &x509crl::getSig, &x509crl::nullMethod);
			LUTOK_PROPERTY("sigMD", &x509crl::getSigMD, &x509crl::nullMethod);
			LUTOK_PROPERTY("sigPK", &x509crl::getSigPK, &x509crl::nullMethod);
			LUTOK_PROPERTY("next", &x509crl::getNext, &x509crl::nullMethod);
		}

		mbedtls_x509_crl * constructor(State & state, bool & managed);

		void destructor(State & state, mbedtls_x509_crl * certificate);

		int parse(State & state, mbedtls_x509_crl * certificate);
		int parseDER(State & state, mbedtls_x509_crl * certificate);
		int parseFile(State & state, mbedtls_x509_crl * certificate);
		int info(State & state, mbedtls_x509_crl * certificate);

		int getRaw(State & state, mbedtls_x509_crl * certificate);
		int getTBS(State & state, mbedtls_x509_crl * certificate);
		int getVersion(State & state, mbedtls_x509_crl * certificate);
		int getSigOID(State & state, mbedtls_x509_crl * certificate);
		int getIssuerRaw(State & state, mbedtls_x509_crl * certificate);
		int getIssuer(State & state, mbedtls_x509_crl * certificate);
		int getThisUpdate(State & state, mbedtls_x509_crl * certificate);
		int getNextUpdate(State & state, mbedtls_x509_crl * certificate);
		int getEntry(State & state, mbedtls_x509_crl * certificate);
		int getCrlExt(State & state, mbedtls_x509_crl * certificate);
		int getSigOID2(State & state, mbedtls_x509_crl * certificate);
		int getSig(State & state, mbedtls_x509_crl * certificate);
		int getSigMD(State & state, mbedtls_x509_crl * certificate);
		int getSigPK(State & state, mbedtls_x509_crl * certificate);
		int getNext(State & state, mbedtls_x509_crl * certificate);
	};
};

#endif	
