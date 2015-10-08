#ifndef LUA_MBEDTLS_OBJECTS_x509writeCert_H
#define LUA_MBEDTLS_OBJECTS_x509writeCert_H

#include "common.hpp"

namespace luambedtls {
	class x509writeCert : public Object<mbedtls_x509write_cert> {
	public:
		explicit x509writeCert(State * state) : Object<mbedtls_x509write_cert>(state){
			LUTOK_PROPERTY("version", &x509writeCert::nullMethod, &x509writeCert::setVersion);
			LUTOK_PROPERTY("MDAlg", &x509writeCert::nullMethod, &x509writeCert::setMDAlg);
			LUTOK_PROPERTY("subjectKey", &x509writeCert::nullMethod, &x509writeCert::setSubjectKey);
			LUTOK_PROPERTY("issuerKey", &x509writeCert::nullMethod, &x509writeCert::setIssuerKey);
			LUTOK_PROPERTY("subjectName", &x509writeCert::nullMethod, &x509writeCert::setSubjectName);
			LUTOK_PROPERTY("issuerName", &x509writeCert::nullMethod, &x509writeCert::setIssuerName);
			LUTOK_PROPERTY("serial", &x509writeCert::nullMethod, &x509writeCert::setSerial);

			LUTOK_METHOD("validity", &x509writeCert::setValidity);
			LUTOK_METHOD("extensions", &x509writeCert::setExtensions);
			LUTOK_METHOD("basicContraints", &x509writeCert::setBasicConstraints);
			LUTOK_METHOD("subjectKeyIdentifier", &x509writeCert::setSubjectKeyIdentifier);
			LUTOK_METHOD("authorityKeyIdentifier", &x509writeCert::setAuthorityKeyIdentifier);
			LUTOK_METHOD("keyUsage", &x509writeCert::setKeyUsage);
			LUTOK_METHOD("NSCertType", &x509writeCert::setNSCertType);

			LUTOK_METHOD("writePEM", &x509writeCert::writePEM);
			LUTOK_METHOD("writeDER", &x509writeCert::writeDER);
		}

		mbedtls_x509write_cert * constructor(State & state, bool & managed);

		void destructor(State & state, mbedtls_x509write_cert * object);
		
		int setVersion(State & state, mbedtls_x509write_cert * object);
		int setMDAlg(State & state, mbedtls_x509write_cert * object);
		int setSubjectKey(State & state, mbedtls_x509write_cert * object);
		int setIssuerKey(State & state, mbedtls_x509write_cert * object);
		int setSubjectName(State & state, mbedtls_x509write_cert * object);
		int setIssuerName(State & state, mbedtls_x509write_cert * object);
		int setSerial(State & state, mbedtls_x509write_cert * object);
		int setValidity(State & state, mbedtls_x509write_cert * object);
		int setExtensions(State & state, mbedtls_x509write_cert * object);
		int setBasicConstraints(State & state, mbedtls_x509write_cert * object);
		int setSubjectKeyIdentifier(State & state, mbedtls_x509write_cert * object);
		int setAuthorityKeyIdentifier(State & state, mbedtls_x509write_cert * object);
		int setKeyUsage(State & state, mbedtls_x509write_cert * object);
		int setNSCertType(State & state, mbedtls_x509write_cert * object);

		int writePEM(State & state, mbedtls_x509write_cert * object);
		int writeDER(State & state, mbedtls_x509write_cert * object);
	};
};

#endif	
