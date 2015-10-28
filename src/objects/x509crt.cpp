#include "objects/x509crt.hpp"
#include "objects/x509crl.hpp"
#include "objects/x509crtProfile.hpp"
#include "objects/ASN1buf.hpp"
#include "objects/ASN1named.hpp"
#include "objects/ASN1sequence.hpp"
#include "objects/PKContext.hpp"

namespace luambedtls {
	mbedtls_x509_crt * x509crt::constructor(State & state, bool & managed){
		mbedtls_x509_crt * x509_crt = new mbedtls_x509_crt;
		mbedtls_x509_crt_init(x509_crt);
		return x509_crt;
	}

	void x509crt::destructor(State & state, mbedtls_x509_crt * x509_crt){
		mbedtls_x509_crt_free(x509_crt);
		delete x509_crt;
	}

	int x509crt::parse(State & state, mbedtls_x509_crt * x509_crt){
		Stack * stack = state.stack;
		if (stack->is<LUA_TSTRING>(1)){
			const std::string buffer = stack->toLString(1);
			stack->push<int>(mbedtls_x509_crt_parse(x509_crt, reinterpret_cast<const unsigned char*>(buffer.c_str()), buffer.length()));
			return 1;
		}
		else{
			stack->push<int>(mbedtls_x509_crt_parse(x509_crt, reinterpret_cast<const unsigned char *>(mbedtls_test_cas_pem), mbedtls_test_cas_pem_len));
			return 1;
		}
		return 0;
	}

	int x509crt::parseDER(State & state, mbedtls_x509_crt * x509_crt){
		Stack * stack = state.stack;
		if (stack->is<LUA_TSTRING>(1)){
			const std::string buffer = stack->toLString(1);
			stack->push<int>(mbedtls_x509_crt_parse_der(x509_crt, reinterpret_cast<const unsigned char*>(buffer.c_str()), buffer.length()));
			return 1;
		}
		return 0;
	}

	int x509crt::parseFile(State & state, mbedtls_x509_crt * x509_crt){
		Stack * stack = state.stack;
		if (stack->is<LUA_TSTRING>(1)){
			const std::string fileName = stack->toLString(1);
			stack->push<int>(mbedtls_x509_crt_parse_file(x509_crt, fileName.c_str()));
			return 1;
		}
		return 0;
	}

	int x509crt::parsePath(State & state, mbedtls_x509_crt * x509_crt){
		Stack * stack = state.stack;
		if (stack->is<LUA_TSTRING>(1)){
			const std::string path = stack->toLString(1);
			stack->push<int>(mbedtls_x509_crt_parse_path(x509_crt, path.c_str()));
			return 1;
		}
		return 0;
	}

	int x509crt::info(State & state, mbedtls_x509_crt * x509_crt){
		Stack * stack = state.stack;
		size_t length = 4096;
		if (stack->is<LUA_TNUMBER>(1)){
			length = stack->to<int>(1);
		}
		char * buffer = new char[length];

		std::string linePrefix = "";
		if (stack->is<LUA_TSTRING>(2)){
			linePrefix = stack->to<const std::string>(2);
		}

		int result = mbedtls_x509_crt_info(buffer, length, linePrefix.c_str(), x509_crt);
		if (result >= 0){
			stack->pushLString(std::string(buffer, result));
		}
		else{
			stack->push<int>(result);
		}
		delete[] buffer;
		return 1;
	}

	int x509crt::checkKeyUsage(State & state, mbedtls_x509_crt * x509_crt){
		Stack * stack = state.stack;
		stack->push<int>(mbedtls_x509_crt_check_key_usage(x509_crt, stack->to<int>(1)));
		return 1;
	}

	int x509crt::checkExtendedKeyUsage(State & state, mbedtls_x509_crt * x509_crt){
		Stack * stack = state.stack;
		if (stack->is<LUA_TTABLE>(1)){
			size_t len = stack->objLen(1);
			char * usageOID = new char[len];
			for (size_t i = 0; i < len; i++){
				stack->getField(i + 1, 1);
				usageOID[i] = stack->to<int>(-1);
				stack->pop(1);
			}

			stack->push<int>(mbedtls_x509_crt_check_extended_key_usage(x509_crt, usageOID, len));

			delete[] usageOID;
			return 1;
		}
		return 0;
	}

	int x509crt::isRevoked(State & state, mbedtls_x509_crt * x509_crt){
		Stack * stack = state.stack;
		x509crl * interfaceCrl = OBJECT_IFACE(x509crl);

		mbedtls_x509_crl * crl = interfaceCrl->get(1);
		if (crl){
			stack->push<int>(mbedtls_x509_crt_is_revoked(x509_crt, crl));
			return 1;
		}
		return 0;
	}

	static int x509VerifyInfo(State & state){
		Stack * stack = state.stack;
		if (stack->is<LUA_TSTRING>(2)){
			const std::string linePrefix = stack->to<const std::string>(2);
			size_t length = stack->to<int>(1);
			char * buffer = new char[length];
			int result = mbedtls_x509_crt_verify_info(buffer, length, linePrefix.c_str(), stack->to<int>(3));
			if (result >= 0){
				stack->pushLString(std::string(buffer, result));
			}
			else{
				stack->push<int>(result);
			}
			delete[] buffer;
			return 1;
		}
		return 0;
	}

	static int crt_verify_fn(void *data, mbedtls_x509_crt *crt, int depth, uint32_t *flags){
		if (data != nullptr){
			x509crtVerifyData * verifyData = reinterpret_cast<x509crtVerifyData*>(data);
			State & state = verifyData->state;
			Stack * stack = state.stack;
			x509crt * interfaceCrt = OBJECT_IFACE(x509crt);

			stack->regValue(verifyData->fnRef);
			if (stack->is<LUA_TFUNCTION>(-1)){

				interfaceCrt->push(crt);
				stack->push<int>(depth);

				if ((*flags) != 0){
					const size_t bufferSize = 4096;
					char buffer[bufferSize];
					mbedtls_x509_crt_verify_info(buffer, bufferSize, "", *flags);

					stack->push<LUA_NUMBER>(*flags);
					stack->push<const std::string &>(buffer);

					stack->call(4, 1);
				}
				else{
					stack->call(2, 1);
				}

				int result = stack->to<int>(-1);
				stack->pop(1);
				return result;
			}
		}
		return 0;
	}


	static int x509Verify(State & state){
		Stack * stack = state.stack;
		x509crt * interfaceCrt = OBJECT_IFACE(x509crt);
		x509crl * interfaceCrl = OBJECT_IFACE(x509crl);

		mbedtls_x509_crt * crt = interfaceCrt->get(1);
		mbedtls_x509_crt * CAcrt = interfaceCrt->get(2);
		mbedtls_x509_crl * CAcrl = interfaceCrl->get(3);

		uint32_t flags = 0;
		int result;

		if (crt && CAcrt){
			x509crtVerifyData fnData = { state, LUA_REFNIL };

			if (stack->is<LUA_TFUNCTION>(5)){
				stack->pushValue(5);
				fnData.fnRef = stack->ref();
			}

			if (stack->is<LUA_TSTRING>(4)){
				const std::string cn = stack->to<const std::string>(4);
				result = mbedtls_x509_crt_verify(crt, CAcrt, CAcrl, cn.c_str(), &flags, crt_verify_fn, &fnData);
			}
			else{
				result = mbedtls_x509_crt_verify(crt, CAcrt, CAcrl, nullptr, &flags, crt_verify_fn, &fnData);
			}

			if (fnData.fnRef != LUA_REFNIL){
				stack->unref(fnData.fnRef);
			}

			stack->push<int>(result);
			stack->push<LUA_NUMBER>(flags);
			return 2;

		}
		return 0;
	}

	static int x509VerifyWithProfile(State & state){
		Stack * stack = state.stack;
		x509crt * interfaceCrt = OBJECT_IFACE(x509crt);
		x509crl * interfaceCrl = OBJECT_IFACE(x509crl);
		x509crtProfile * interfaceCrtProfile = OBJECT_IFACE(x509crtProfile);

		mbedtls_x509_crt * crt = interfaceCrt->get(1);
		mbedtls_x509_crt * CAcrt = interfaceCrt->get(2);
		mbedtls_x509_crl * CAcrl = interfaceCrl->get(3);
		mbedtls_x509_crt_profile * profile = interfaceCrtProfile->get(4);

		uint32_t flags = 0;
		int result;

		if (crt && CAcrt && profile){
			x509crtVerifyData fnData = { state, LUA_REFNIL };

			if (stack->is<LUA_TFUNCTION>(6)){
				stack->pushValue(6);
				fnData.fnRef = stack->ref();
			}

			if (stack->is<LUA_TSTRING>(5)){
				const std::string cn = stack->to<const std::string>(5);
				result = mbedtls_x509_crt_verify_with_profile(crt, CAcrt, CAcrl, profile, cn.c_str(), &flags, crt_verify_fn, &fnData);
			}
			else{
				result = mbedtls_x509_crt_verify_with_profile(crt, CAcrt, CAcrl, profile, nullptr, &flags, crt_verify_fn, &fnData);
			}

			if (fnData.fnRef != LUA_REFNIL){
				stack->unref(fnData.fnRef);
			}

			stack->push<int>(result);
			stack->push<LUA_NUMBER>(flags);
			return 2;

		}
		return 0;
	}

	int x509crt::verify(State & state, mbedtls_x509_crt * x509_crt){
		Stack * stack = state.stack;
		x509crt * interfaceCrt = OBJECT_IFACE(x509crt);
		x509crl * interfaceCrl = OBJECT_IFACE(x509crl);

		mbedtls_x509_crt * CAcrt = interfaceCrt->get(1);
		mbedtls_x509_crl * CAcrl = interfaceCrl->get(2);

		uint32_t flags = 0;
		int result;

		if (x509_crt && CAcrt){
			x509crtVerifyData fnData = { state, LUA_REFNIL };

			if (stack->is<LUA_TFUNCTION>(4)){
				stack->pushValue(4);
				fnData.fnRef = stack->ref();
			}

			if (stack->is<LUA_TSTRING>(3)){
				const std::string cn = stack->to<const std::string>(3);
				result = mbedtls_x509_crt_verify(x509_crt, CAcrt, CAcrl, cn.c_str(), &flags, crt_verify_fn, &fnData);
			}
			else{
				result = mbedtls_x509_crt_verify(x509_crt, CAcrt, CAcrl, nullptr, &flags, crt_verify_fn, &fnData);
			}

			if (fnData.fnRef != LUA_REFNIL){
				stack->unref(fnData.fnRef);
			}

			stack->push<int>(result);
			stack->push<LUA_NUMBER>(flags);
			return 2;

		}
		return 0;
	}

	int x509crt::verifyWithProfile(State & state, mbedtls_x509_crt * x509_crt){
		Stack * stack = state.stack;
		x509crt * interfaceCrt = OBJECT_IFACE(x509crt);
		x509crl * interfaceCrl = OBJECT_IFACE(x509crl);
		x509crtProfile * interfaceCrtProfile = OBJECT_IFACE(x509crtProfile);

		mbedtls_x509_crt * CAcrt = interfaceCrt->get(1);
		mbedtls_x509_crl * CAcrl = interfaceCrl->get(2);
		mbedtls_x509_crt_profile * profile = interfaceCrtProfile->get(3);

		uint32_t flags = 0;
		int result;

		if (x509_crt && CAcrt && profile){
			x509crtVerifyData fnData = { state, LUA_REFNIL };

			if (stack->is<LUA_TFUNCTION>(5)){
				stack->pushValue(5);
				fnData.fnRef = stack->ref();
			}

			if (stack->is<LUA_TSTRING>(4)){
				const std::string cn = stack->to<const std::string>(4);
				result = mbedtls_x509_crt_verify_with_profile(x509_crt, CAcrt, CAcrl, profile, cn.c_str(), &flags, crt_verify_fn, &fnData);
			}
			else{
				result = mbedtls_x509_crt_verify_with_profile(x509_crt, CAcrt, CAcrl, profile, nullptr, &flags, crt_verify_fn, &fnData);
			}

			if (fnData.fnRef != LUA_REFNIL){
				stack->unref(fnData.fnRef);
			}

			stack->push<int>(result);
			stack->push<LUA_NUMBER>(flags);
			return 2;
		}
		return 0;
	}

	int x509crt::getRaw(State & state, mbedtls_x509_crt * x509_crt){
		Stack * stack = state.stack;
		ASN1buf * interfaceASN1buf = OBJECT_IFACE(ASN1buf);
		interfaceASN1buf->pushX509(&x509_crt->raw);
		return 1;
	}
	int x509crt::getTBS(State & state, mbedtls_x509_crt * x509_crt){
		Stack * stack = state.stack;
		ASN1buf * interfaceASN1buf = OBJECT_IFACE(ASN1buf);
		interfaceASN1buf->pushX509(&x509_crt->tbs);
		return 1;
	}
	int x509crt::getVersion(State & state, mbedtls_x509_crt * x509_crt){
		Stack * stack = state.stack;
		stack->push<int>(x509_crt->version);
		return 1;
	}
	int x509crt::getSerial(State & state, mbedtls_x509_crt * x509_crt){
		Stack * stack = state.stack;
		ASN1buf * interfaceASN1buf = OBJECT_IFACE(ASN1buf);
		interfaceASN1buf->pushX509(&x509_crt->serial);
		return 1;
	}

	int x509crt::getIssuer(State & state, mbedtls_x509_crt * x509_crt){
		Stack * stack = state.stack;
		ASN1named * interfaceASN1named = OBJECT_IFACE(ASN1named);
		interfaceASN1named->push(&x509_crt->issuer);
		return 1;
	}
	int x509crt::getSubject(State & state, mbedtls_x509_crt * x509_crt){
		Stack * stack = state.stack;
		ASN1named * interfaceASN1named = OBJECT_IFACE(ASN1named);
		interfaceASN1named->push(&x509_crt->subject);
		return 1;
	}
	int x509crt::getIssuerRaw(State & state, mbedtls_x509_crt * x509_crt){
		Stack * stack = state.stack;
		ASN1buf * interfaceASN1buf = OBJECT_IFACE(ASN1buf);
		interfaceASN1buf->pushX509(&x509_crt->issuer_raw);
		return 1;
	}
	int x509crt::getSubjectRaw(State & state, mbedtls_x509_crt * x509_crt){
		Stack * stack = state.stack;
		ASN1buf * interfaceASN1buf = OBJECT_IFACE(ASN1buf);
		interfaceASN1buf->pushX509(&x509_crt->subject_raw);
		return 1;
	}

	int x509crt::getValidFrom(State & state, mbedtls_x509_crt * x509_crt){
		Stack * stack = state.stack;
		return pushX509time(state, &x509_crt->valid_from);
	}
	int x509crt::getValidTo(State & state, mbedtls_x509_crt * x509_crt){
		Stack * stack = state.stack;
		return pushX509time(state, &x509_crt->valid_to);
	}

	int x509crt::getIssuerID(State & state, mbedtls_x509_crt * x509_crt){
		Stack * stack = state.stack;
		ASN1buf * interfaceASN1buf = OBJECT_IFACE(ASN1buf);
		interfaceASN1buf->pushX509(&x509_crt->issuer_id);
		return 1;
	}
	int x509crt::getSubjectID(State & state, mbedtls_x509_crt * x509_crt){
		Stack * stack = state.stack;
		ASN1buf * interfaceASN1buf = OBJECT_IFACE(ASN1buf);
		interfaceASN1buf->pushX509(&x509_crt->subject_id);
		return 1;
	}
	int x509crt::getV3ext(State & state, mbedtls_x509_crt * x509_crt){
		Stack * stack = state.stack;
		ASN1buf * interfaceASN1buf = OBJECT_IFACE(ASN1buf);
		interfaceASN1buf->pushX509(&x509_crt->v3_ext);
		return 0;
	}

	int x509crt::getSubjectAltNames(State & state, mbedtls_x509_crt * x509_crt){
		Stack * stack = state.stack;
		ASN1sequence * interfaceASN1sequence = OBJECT_IFACE(ASN1sequence);
		interfaceASN1sequence->push(&x509_crt->subject_alt_names);
		return 1;
	}

	int x509crt::getExtTypes(State & state, mbedtls_x509_crt * x509_crt){
		Stack * stack = state.stack;
		stack->push<int>(x509_crt->ext_types);
		return 1;
	}
	int x509crt::getCAisTrue(State & state, mbedtls_x509_crt * x509_crt){
		Stack * stack = state.stack;
		stack->push<int>(x509_crt->ca_istrue);
		return 1;
	}
	int x509crt::getMaxPathLen(State & state, mbedtls_x509_crt * x509_crt){
		Stack * stack = state.stack;
		stack->push<int>(x509_crt->max_pathlen);
		return 1;
	}
	int x509crt::getKeyUsage(State & state, mbedtls_x509_crt * x509_crt){
		Stack * stack = state.stack;
		stack->push<int>(x509_crt->key_usage);
		return 1;
	}
	int x509crt::getExtKeyUsage(State & state, mbedtls_x509_crt * x509_crt){
		Stack * stack = state.stack;
		ASN1sequence * interfaceASN1sequence = OBJECT_IFACE(ASN1sequence);
		interfaceASN1sequence->push(&x509_crt->ext_key_usage);
		return 1;
	}
	int x509crt::getNSCertType(State & state, mbedtls_x509_crt * x509_crt){
		Stack * stack = state.stack;
		ASN1buf * interfaceASN1buf = OBJECT_IFACE(ASN1buf);
		stack->push<int>(x509_crt->ns_cert_type);
		return 1;
	}
	int x509crt::getSig(State & state, mbedtls_x509_crt * x509_crt){
		Stack * stack = state.stack;
		ASN1buf * interfaceASN1buf = OBJECT_IFACE(ASN1buf);
		interfaceASN1buf->pushX509(&x509_crt->sig);
		return 1;
	}
	int x509crt::getSigMD(State & state, mbedtls_x509_crt * x509_crt){
		Stack * stack = state.stack;
		stack->push<int>(x509_crt->sig_md);
		return 1;
	}
	int x509crt::getSigPK(State & state, mbedtls_x509_crt * x509_crt){
		Stack * stack = state.stack;
		stack->push<int>(x509_crt->sig_pk);
		return 1;
	}

	int x509crt::getPK(State & state, mbedtls_x509_crt * x509_crt){
		Stack * stack = state.stack;
		PKContext * interfacePK = OBJECT_IFACE(PKContext);
		interfacePK->push(&x509_crt->pk);
		return 1;
	}


	int x509crt::getNext(State & state, mbedtls_x509_crt * x509_crt){
		Stack * stack = state.stack;
		x509crt * interfaceX509crt = OBJECT_IFACE(x509crt);
		if (x509_crt->next){
			interfaceX509crt->push(x509_crt->next);
		}
		else{
			stack->pushNil();
		}
		return 1;
	}

	void initx509crt(State * state, Module & module){
		INIT_OBJECT(x509crt);
		module["x509VerifyInfo"] = x509VerifyInfo;
		module["x509Verify"] = x509Verify;
		module["x509VerifyWithProfile"] = x509VerifyWithProfile;
	}
};
