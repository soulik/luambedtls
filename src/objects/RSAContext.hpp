#ifndef LUA_MBEDTLS_OBJECTS_RSACONTEXT_H
#define LUA_MBEDTLS_OBJECTS_RSACONTEXT_H

#include "common.hpp"

namespace luambedtls {
	class RSAContext : public Object<mbedtls_rsa_context> {
	public:
		explicit RSAContext(State * state) : Object<mbedtls_rsa_context>(state){
			LUTOK_METHOD("copy", &RSAContext::copy);
			LUTOK_METHOD("setPadding", &RSAContext::setPadding);
			LUTOK_METHOD("genKey", &RSAContext::genKey);
			LUTOK_METHOD("checkPubKey", &RSAContext::checkPubKey);
			LUTOK_METHOD("checkPrivKey", &RSAContext::checkPrivKey);
			LUTOK_METHOD("checkPubPriv", &RSAContext::checkPubPriv);

			LUTOK_METHOD("public", &RSAContext::publicKeyOp);
			LUTOK_METHOD("private", &RSAContext::privateKeyOp);

			LUTOK_METHOD("encryptPKCS1", &RSAContext::encryptPKCS1);
			LUTOK_METHOD("encryptRSAESPKCS1v15", &RSAContext::encryptRSAESPKCS1v15);
			LUTOK_METHOD("encryptRSAESOAEP", &RSAContext::encryptRSAESOAEP);
			LUTOK_METHOD("decryptPKCS1", &RSAContext::decryptPKCS1);
			LUTOK_METHOD("decryptRSAESPKCS1v15", &RSAContext::decryptRSAESPKCS1v15);
			LUTOK_METHOD("decryptRSAESOAEP", &RSAContext::decryptRSAESOAEP);

			LUTOK_METHOD("signPKCS1", &RSAContext::signPKCS1);
			LUTOK_METHOD("signRSASSAPKCS1v15", &RSAContext::signRSASSAPKCS1v15);
			LUTOK_METHOD("signRSASSAPSS", &RSAContext::signRSASSAPSS);
			LUTOK_METHOD("verifyPKCS1", &RSAContext::verifyPKCS1);
			LUTOK_METHOD("verifyRSASSAPKCS1v15", &RSAContext::verifyRSASSAPKCS1v15);
			LUTOK_METHOD("verifyRSASSAPSS", &RSAContext::verifyRSASSAPSS);
			LUTOK_METHOD("verifyRSASSAPSSext", &RSAContext::verifyRSASSAPSSext);

			LUTOK_PROPERTY("len", &RSAContext::getLen, &RSAContext::setLen);

			LUTOK_PROPERTY("N", &RSAContext::getN, &RSAContext::setN);
			LUTOK_PROPERTY("E", &RSAContext::getE, &RSAContext::setE);

			LUTOK_PROPERTY("D", &RSAContext::getD, &RSAContext::setD);
			LUTOK_PROPERTY("P", &RSAContext::getP, &RSAContext::setP);
			LUTOK_PROPERTY("Q", &RSAContext::getQ, &RSAContext::setQ);
			LUTOK_PROPERTY("DP", &RSAContext::getDP, &RSAContext::setDP);
			LUTOK_PROPERTY("DQ", &RSAContext::getDQ, &RSAContext::setDQ);
			LUTOK_PROPERTY("QP", &RSAContext::getQP, &RSAContext::setQP);

			LUTOK_PROPERTY("RN", &RSAContext::getRN, &RSAContext::setRN);
			LUTOK_PROPERTY("RP", &RSAContext::getRP, &RSAContext::setRP);
			LUTOK_PROPERTY("RQ", &RSAContext::getRQ, &RSAContext::setRQ);

			LUTOK_PROPERTY("Vi", &RSAContext::getVi, &RSAContext::setVi);
			LUTOK_PROPERTY("Vf", &RSAContext::getVf, &RSAContext::setVf);
			
			LUTOK_PROPERTY("padding", &RSAContext::getPaddingOnly, &RSAContext::setPaddingOnly);
			LUTOK_PROPERTY("hashID", &RSAContext::getHashID, &RSAContext::setHashID);
		}

		mbedtls_rsa_context * constructor(State & state, bool & managed);

		void destructor(State & state, mbedtls_rsa_context * context);
		
		int copy(State & state, mbedtls_rsa_context * context);

		int setPadding(State & state, mbedtls_rsa_context * context);
		int genKey(State & state, mbedtls_rsa_context * context);
		int checkPubKey(State & state, mbedtls_rsa_context * context);
		int checkPrivKey(State & state, mbedtls_rsa_context * context);
		int checkPubPriv(State & state, mbedtls_rsa_context * context);
		
		int publicKeyOp(State & state, mbedtls_rsa_context * context);
		int privateKeyOp(State & state, mbedtls_rsa_context * context);

		int encryptPKCS1(State & state, mbedtls_rsa_context * context);
		int encryptRSAESPKCS1v15(State & state, mbedtls_rsa_context * context);
		int encryptRSAESOAEP(State & state, mbedtls_rsa_context * context);
		int decryptPKCS1(State & state, mbedtls_rsa_context * context);
		int decryptRSAESPKCS1v15(State & state, mbedtls_rsa_context * context);
		int decryptRSAESOAEP(State & state, mbedtls_rsa_context * context);

		int signPKCS1(State & state, mbedtls_rsa_context * context);
		int signRSASSAPKCS1v15(State & state, mbedtls_rsa_context * context);
		int signRSASSAPSS(State & state, mbedtls_rsa_context * context);
		int verifyPKCS1(State & state, mbedtls_rsa_context * context);
		int verifyRSASSAPKCS1v15(State & state, mbedtls_rsa_context * context);
		int verifyRSASSAPSS(State & state, mbedtls_rsa_context * context);
		int verifyRSASSAPSSext(State & state, mbedtls_rsa_context * context);

		int getLen(State & state, mbedtls_rsa_context * context);
		int setLen(State & state, mbedtls_rsa_context * context);

		int getN(State & state, mbedtls_rsa_context * context);
		int setN(State & state, mbedtls_rsa_context * context);
		int getE(State & state, mbedtls_rsa_context * context);
		int setE(State & state, mbedtls_rsa_context * context);

		int getD(State & state, mbedtls_rsa_context * context);
		int setD(State & state, mbedtls_rsa_context * context);
		int getP(State & state, mbedtls_rsa_context * context);
		int setP(State & state, mbedtls_rsa_context * context);
		int getQ(State & state, mbedtls_rsa_context * context);
		int setQ(State & state, mbedtls_rsa_context * context);
		int getDP(State & state, mbedtls_rsa_context * context);
		int setDP(State & state, mbedtls_rsa_context * context);
		int getDQ(State & state, mbedtls_rsa_context * context);
		int setDQ(State & state, mbedtls_rsa_context * context);
		int getQP(State & state, mbedtls_rsa_context * context);
		int setQP(State & state, mbedtls_rsa_context * context);

		int getRN(State & state, mbedtls_rsa_context * context);
		int setRN(State & state, mbedtls_rsa_context * context);
		int getRP(State & state, mbedtls_rsa_context * context);
		int setRP(State & state, mbedtls_rsa_context * context);
		int getRQ(State & state, mbedtls_rsa_context * context);
		int setRQ(State & state, mbedtls_rsa_context * context);

		int getVi(State & state, mbedtls_rsa_context * context);
		int setVi(State & state, mbedtls_rsa_context * context);
		int getVf(State & state, mbedtls_rsa_context * context);
		int setVf(State & state, mbedtls_rsa_context * context);

		int getPaddingOnly(State & state, mbedtls_rsa_context * context);
		int setPaddingOnly(State & state, mbedtls_rsa_context * context);

		int getHashID(State & state, mbedtls_rsa_context * context);
		int setHashID(State & state, mbedtls_rsa_context * context);
	};
};

#endif	
