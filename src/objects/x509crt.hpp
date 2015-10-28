#ifndef LUA_MBEDTLS_OBJECTS_X509CRT_H
#define LUA_MBEDTLS_OBJECTS_X509CRT_H

#include "common.hpp"

namespace luambedtls {

	struct x509crtVerifyData{
		State & state;
		int fnRef;
	};

	class x509crt : public Object<mbedtls_x509_crt> {
	public:
		explicit x509crt(State * state) : Object<mbedtls_x509_crt>(state){
			LUTOK_METHOD("parse", &x509crt::parse);
			LUTOK_METHOD("parseDER", &x509crt::parseDER);
			LUTOK_METHOD("parseFile", &x509crt::parseFile);
			LUTOK_METHOD("parsePath", &x509crt::parsePath);
			LUTOK_METHOD("info", &x509crt::info);
			LUTOK_METHOD("checkKeyUsage", &x509crt::checkKeyUsage);
			LUTOK_METHOD("checkExtendedKeyUsage", &x509crt::checkExtendedKeyUsage);
			LUTOK_METHOD("isRevoked", &x509crt::isRevoked);
			LUTOK_METHOD("verify", &x509crt::verify);
			LUTOK_METHOD("verifyWithProfile", &x509crt::verifyWithProfile);

			LUTOK_PROPERTY("raw", &x509crt::getRaw, &x509crt::nullMethod);
			LUTOK_PROPERTY("TBS", &x509crt::getTBS, &x509crt::nullMethod);
			LUTOK_PROPERTY("version", &x509crt::getVersion, &x509crt::nullMethod);
			LUTOK_PROPERTY("serial", &x509crt::getSerial, &x509crt::nullMethod);
			LUTOK_PROPERTY("issuer", &x509crt::getIssuer, &x509crt::nullMethod);
			LUTOK_PROPERTY("subject", &x509crt::getSubject, &x509crt::nullMethod);
			LUTOK_PROPERTY("issuerRaw", &x509crt::getIssuerRaw, &x509crt::nullMethod);
			LUTOK_PROPERTY("subjectRaw", &x509crt::getSubjectRaw, &x509crt::nullMethod);
			LUTOK_PROPERTY("validFrom", &x509crt::getValidFrom, &x509crt::nullMethod);
			LUTOK_PROPERTY("validTo", &x509crt::getValidTo, &x509crt::nullMethod);
			LUTOK_PROPERTY("issuerID", &x509crt::getIssuerID, &x509crt::nullMethod);
			LUTOK_PROPERTY("subjectID", &x509crt::getSubjectID, &x509crt::nullMethod);
			LUTOK_PROPERTY("subjectAltNames", &x509crt::getSubjectAltNames, &x509crt::nullMethod);
			LUTOK_PROPERTY("v3ext", &x509crt::getV3ext, &x509crt::nullMethod);
			LUTOK_PROPERTY("extTypes", &x509crt::getExtTypes, &x509crt::nullMethod);
			LUTOK_PROPERTY("CAisTrue", &x509crt::getCAisTrue, &x509crt::nullMethod);
			LUTOK_PROPERTY("maxPathLen", &x509crt::getMaxPathLen, &x509crt::nullMethod);
			LUTOK_PROPERTY("keyUsage", &x509crt::getKeyUsage, &x509crt::nullMethod);
			LUTOK_PROPERTY("extKeyUsage", &x509crt::getExtKeyUsage, &x509crt::nullMethod);
			LUTOK_PROPERTY("NSCertType", &x509crt::getNSCertType, &x509crt::nullMethod);
			LUTOK_PROPERTY("sig", &x509crt::getSig, &x509crt::nullMethod);
			LUTOK_PROPERTY("sigMD", &x509crt::getSigMD, &x509crt::nullMethod);
			LUTOK_PROPERTY("sigPK", &x509crt::getSigPK, &x509crt::nullMethod);

			LUTOK_PROPERTY("pk", &x509crt::getPK, &x509crt::nullMethod);

			LUTOK_PROPERTY("next", &x509crt::getNext, &x509crt::nullMethod);
		}

		mbedtls_x509_crt * constructor(State & state, bool & managed);

		void destructor(State & state, mbedtls_x509_crt * x509_crt);

		int parse(State & state, mbedtls_x509_crt * x509_crt);
		int parseDER(State & state, mbedtls_x509_crt * x509_crt);
		int parseFile(State & state, mbedtls_x509_crt * x509_crt);
		int parsePath(State & state, mbedtls_x509_crt * x509_crt);
		int info(State & state, mbedtls_x509_crt * x509_crt);
		int checkKeyUsage(State & state, mbedtls_x509_crt * x509_crt);
		int checkExtendedKeyUsage(State & state, mbedtls_x509_crt * x509_crt);
		int isRevoked(State & state, mbedtls_x509_crt * x509_crt);
		int verify(State & state, mbedtls_x509_crt * x509_crt);
		int verifyWithProfile(State & state, mbedtls_x509_crt * x509_crt);

		int getRaw(State & state, mbedtls_x509_crt * x509_crt);
		int getTBS(State & state, mbedtls_x509_crt * x509_crt);
		int getVersion(State & state, mbedtls_x509_crt * x509_crt);
		int getSerial(State & state, mbedtls_x509_crt * x509_crt);

		int getIssuer(State & state, mbedtls_x509_crt * x509_crt);
		int getSubject(State & state, mbedtls_x509_crt * x509_crt);
		int getIssuerRaw(State & state, mbedtls_x509_crt * x509_crt);
		int getSubjectRaw(State & state, mbedtls_x509_crt * x509_crt);
		int getValidFrom(State & state, mbedtls_x509_crt * x509_crt);
		int getValidTo(State & state, mbedtls_x509_crt * x509_crt);

		int getIssuerID(State & state, mbedtls_x509_crt * x509_crt);
		int getSubjectID(State & state, mbedtls_x509_crt * x509_crt);
		int getV3ext(State & state, mbedtls_x509_crt * x509_crt);
		int getSubjectAltNames(State & state, mbedtls_x509_crt * x509_crt);

		int getExtTypes(State & state, mbedtls_x509_crt * x509_crt);
		int getCAisTrue(State & state, mbedtls_x509_crt * x509_crt);
		int getMaxPathLen(State & state, mbedtls_x509_crt * x509_crt);
		int getKeyUsage(State & state, mbedtls_x509_crt * x509_crt);
		int getExtKeyUsage(State & state, mbedtls_x509_crt * x509_crt);
		int getNSCertType(State & state, mbedtls_x509_crt * x509_crt);
		int getSig(State & state, mbedtls_x509_crt * x509_crt);
		int getSigMD(State & state, mbedtls_x509_crt * x509_crt);
		int getSigPK(State & state, mbedtls_x509_crt * x509_crt);

		int getPK(State & state, mbedtls_x509_crt * x509_crt);

		int getNext(State & state, mbedtls_x509_crt * x509_crt);
	};
};

#endif	
