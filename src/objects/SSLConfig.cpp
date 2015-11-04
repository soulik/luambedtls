#include "objects/SSLConfig.hpp"
#include "objects/x509crt.hpp"
#include "objects/x509crl.hpp"
#include "objects/x509crtProfile.hpp"
#include "objects/PKContext.hpp"
#include "objects/DHMContext.hpp"
#include "objects/CTRDRBGContext.hpp"
#include <vector>
#include <string.h>
#include <stdint.h>

namespace luambedtls {
	mbedtls_ssl_config * SSLConfig::constructor(State & state, bool & managed){
		Stack * stack = state.stack;
		mbedtls_ssl_config * ssl_config = new mbedtls_ssl_config;
		mbedtls_ssl_config_init(ssl_config);
		memset(ssl_config, 0, sizeof(mbedtls_ssl_config));

		if (stack->is<LUA_TNUMBER>(1) && stack->is<LUA_TNUMBER>(2) && stack->is<LUA_TNUMBER>(3)){
			int endpoint = stack->to<int>(1);
			int transport = stack->to<int>(2);
			int preset = stack->to<int>(3);
			if (mbedtls_ssl_config_defaults(ssl_config, endpoint, transport, preset) == 0){
				return ssl_config;
			}
			else{
				delete ssl_config;
				return nullptr;
			}
		}

		return ssl_config;
	}

	void SSLConfig::destructor(State & state, mbedtls_ssl_config * ssl_config){
		mbedtls_ssl_conf_dbg(ssl_config, nullptr, nullptr);
		mbedtls_ssl_config_free(ssl_config);
		delete ssl_config;
	}

	int SSLConfig::verify(State & state, mbedtls_ssl_config * ssl_config){
		return 0;
	}

	int SSLConfig::setupEndpoint(State & state, mbedtls_ssl_config * ssl_config){
		Stack * stack = state.stack;
		mbedtls_ssl_conf_endpoint(ssl_config, stack->to<int>(1));
		return 0;
	}

	int SSLConfig::setupTransport(State & state, mbedtls_ssl_config * ssl_config){
		Stack * stack = state.stack;
		mbedtls_ssl_conf_transport(ssl_config, stack->to<int>(1));
		return 0;
	}

	int SSLConfig::setupAuthmode(State & state, mbedtls_ssl_config * ssl_config){
		Stack * stack = state.stack;
		mbedtls_ssl_conf_authmode(ssl_config, stack->to<int>(1));
		return 0;
	}

	int SSLConfig::setDLTSAntireplay(State & state, mbedtls_ssl_config * ssl_config){
		Stack * stack = state.stack;
		mbedtls_ssl_conf_dtls_anti_replay(ssl_config, stack->to<int>(1));
		return 0;
	}

	int SSLConfig::setBadMACLimit(State & state, mbedtls_ssl_config * ssl_config){
		Stack * stack = state.stack;
		mbedtls_ssl_conf_dtls_badmac_limit(ssl_config, stack->to<int>(1));
		return 0;
	}

	int SSLConfig::setHandshakeTimeout(State & state, mbedtls_ssl_config * ssl_config){
		Stack * stack = state.stack;
		mbedtls_ssl_conf_handshake_timeout(ssl_config, stack->to<int>(1), stack->to<int>(2));
		return 0;
	}

	int SSLConfig::setCipherSuites(State & state, mbedtls_ssl_config * ssl_config){
		Stack * stack = state.stack;
		if (stack->is<LUA_TTABLE>(1)){
			int count = stack->objLen(1);
			int *ciphersuites = new int[count+1];

			for (int i = 0; i < count; i++){
				stack->getField(i + 1, 1);
				ciphersuites[i] = stack->to<int>(-1);
				stack->pop(1);
			}

			ciphersuites[count] = 0;

			if (stack->is<LUA_TNUMBER>(2) && stack->is<LUA_TNUMBER>(3)){
				mbedtls_ssl_conf_ciphersuites_for_version(ssl_config, ciphersuites, stack->to<int>(2), stack->to<int>(3));
			}
			else{
				mbedtls_ssl_conf_ciphersuites(ssl_config, ciphersuites);
			}

			delete[] ciphersuites;
		}
		return 0;
	}

	int SSLConfig::setCertProfile(State & state, mbedtls_ssl_config * ssl_config){
		Stack * stack = state.stack;
		x509crtProfile * interfaceCertProfile = OBJECT_IFACE(x509crtProfile);
		mbedtls_x509_crt_profile * certProfile = interfaceCertProfile->get(1);
		if (certProfile){
			mbedtls_ssl_conf_cert_profile(ssl_config, certProfile);
		}
		return 0;
	}

	int SSLConfig::setCAChain(State & state, mbedtls_ssl_config * ssl_config){
		Stack * stack = state.stack;
		x509crt * interfaceCert = OBJECT_IFACE(x509crt);
		x509crl * interfaceRevokeCert = OBJECT_IFACE(x509crl);
		mbedtls_x509_crt * cert = interfaceCert->get(1);
		mbedtls_x509_crl * revokeCert = interfaceRevokeCert->get(2);

		if (cert){
			if (revokeCert){
				mbedtls_ssl_conf_ca_chain(ssl_config, cert, revokeCert);
			}
			else{
				mbedtls_ssl_conf_ca_chain(ssl_config, cert, nullptr);
			}
		}
		return 0;
	}

	int SSLConfig::setOwnCert(State & state, mbedtls_ssl_config * ssl_config){
		Stack * stack = state.stack;
		x509crt * interfaceCert = OBJECT_IFACE(x509crt);
		PKContext * interfacePKContext = OBJECT_IFACE(PKContext);

		mbedtls_x509_crt * cert = interfaceCert->get(1);
		mbedtls_pk_context * PKcontext = interfacePKContext->get(2);
		
		if (cert && PKcontext){
			stack->push<int>(mbedtls_ssl_conf_own_cert(ssl_config, cert, PKcontext));
			return 1;
		}
		return 0;
	}

	int SSLConfig::setPSK(State & state, mbedtls_ssl_config * ssl_config){
		Stack * stack = state.stack;
		if (stack->is<LUA_TSTRING>(1) && stack->is<LUA_TSTRING>(2)){
			const std::string psk = stack->toLString(1);
			const std::string identity = stack->toLString(2);

			stack->push<int>(mbedtls_ssl_conf_psk(ssl_config, reinterpret_cast<const unsigned char*>(psk.c_str()), psk.length(), reinterpret_cast<const unsigned char*>(identity.c_str()), identity.length()));
			return 1;
		}
		return 0;
	}

	int SSLConfig::setDH(State & state, mbedtls_ssl_config * ssl_config){
		Stack * stack = state.stack;
		if (stack->is<LUA_TSTRING>(1) && stack->is<LUA_TSTRING>(2)){
			const std::string dhmP = stack->to<const std::string>(1);
			const std::string dhmG = stack->to<const std::string>(2);

			stack->push<int>(mbedtls_ssl_conf_dh_param(ssl_config, dhmP.c_str(), dhmG.c_str()));
			return 1;
		}
		return 0;
	}

	int SSLConfig::setDHCTX(State & state, mbedtls_ssl_config * ssl_config){
		Stack * stack = state.stack;
		DHMContext * interfaceDHMContext = OBJECT_IFACE(DHMContext);

		mbedtls_dhm_context * DHMcontext = interfaceDHMContext->get(1);

		if (DHMcontext){
			stack->push<int>(mbedtls_ssl_conf_dh_param_ctx(ssl_config, DHMcontext));
			return 1;
		}
		return 0;
	}

	int SSLConfig::setMinBitLen(State & state, mbedtls_ssl_config * ssl_config){
		Stack * stack = state.stack;
		mbedtls_ssl_conf_dhm_min_bitlen(ssl_config, stack->to<int>(1));
		return 0;
	}


	int SSLConfig::setCurves(State & state, mbedtls_ssl_config * ssl_config){
		Stack * stack = state.stack;
		if (stack->is<LUA_TTABLE>(1)){
			int count = stack->objLen(1);
			mbedtls_ecp_group_id *curves = new mbedtls_ecp_group_id[count + 1];

			for (int i = 0; i < count; i++){
				stack->getField(i + 1, 1);
				curves[i] = static_cast<mbedtls_ecp_group_id>(stack->to<int>(-1));
				stack->pop(1);
			}

			curves[count] = MBEDTLS_ECP_DP_NONE;

			mbedtls_ssl_conf_curves(ssl_config, curves);

			delete[] curves;
		}
		return 0;
	}

	int SSLConfig::setHashes(State & state, mbedtls_ssl_config * ssl_config){
		Stack * stack = state.stack;
		if (stack->is<LUA_TTABLE>(1)){
			int count = stack->objLen(1);
			int *hashes = new int[count + 1];

			for (int i = 0; i < count; i++){
				stack->getField(i + 1, 1);
				hashes[i] = stack->to<int>(-1);
				stack->pop(1);
			}

			hashes[count] = MBEDTLS_MD_NONE;

			mbedtls_ssl_conf_sig_hashes(ssl_config, hashes);

			delete[] hashes;
		}
		return 0;
	}

	int SSLConfig::setALPNprotocols(State & state, mbedtls_ssl_config * ssl_config){
		Stack * stack = state.stack;
		if (stack->is<LUA_TTABLE>(1)){
			const int count = stack->objLen(1);
			std::vector<char *> protocols;

			for (int i = 0; i < count; i++){
				stack->getField(i + 1, 1);
				const std::string value = stack->to<const std::string>(-1);
				protocols[i] = new char[value.length() + 1];
				strncpy(protocols[i], value.c_str(), value.length());
				stack->pop(1);
			}

			protocols.push_back(nullptr);

			int result = mbedtls_ssl_conf_alpn_protocols(ssl_config, const_cast<const char **>(protocols.data()));

			for (int i = 0; i < count; i++){
				delete protocols[i];
			}
			stack->push<int>(result);
			return 1;
		}
		return 0;
	}

	int SSLConfig::setMinVersion(State & state, mbedtls_ssl_config * ssl_config){
		Stack * stack = state.stack;
		mbedtls_ssl_conf_min_version(ssl_config, stack->to<int>(1), stack->to<int>(2));
		return 0;
	}

	int SSLConfig::setMaxVersion(State & state, mbedtls_ssl_config * ssl_config){
		Stack * stack = state.stack;
		mbedtls_ssl_conf_max_version(ssl_config, stack->to<int>(1), stack->to<int>(2));
		return 0;
	}

	int SSLConfig::setFallback(State & state, mbedtls_ssl_config * ssl_config){
		Stack * stack = state.stack;
		mbedtls_ssl_conf_fallback(ssl_config, stack->to<int>(1));
		return 0;
	}

	int SSLConfig::setEncryptThenMAC(State & state, mbedtls_ssl_config * ssl_config){
		Stack * stack = state.stack;
		mbedtls_ssl_conf_encrypt_then_mac(ssl_config, stack->to<int>(1));
		return 0;
	}

	int SSLConfig::setExtendedMasterSecret(State & state, mbedtls_ssl_config * ssl_config){
		Stack * stack = state.stack;
		mbedtls_ssl_conf_extended_master_secret(ssl_config, stack->to<int>(1));
		return 0;
	}

	int SSLConfig::setArc4Support(State & state, mbedtls_ssl_config * ssl_config){
		Stack * stack = state.stack;
		mbedtls_ssl_conf_arc4_support(ssl_config, stack->to<int>(1));
		return 0;
	}

	int SSLConfig::setMaxFragLen(State & state, mbedtls_ssl_config * ssl_config){
		Stack * stack = state.stack;
		mbedtls_ssl_conf_max_frag_len(ssl_config, stack->to<int>(1));
		return 0;
	}

	int SSLConfig::setTrucatedMAC(State & state, mbedtls_ssl_config * ssl_config){
		Stack * stack = state.stack;
		mbedtls_ssl_conf_truncated_hmac(ssl_config, stack->to<int>(1));
		return 0;
	}

	int SSLConfig::setRecordSplitting(State & state, mbedtls_ssl_config * ssl_config){
		Stack * stack = state.stack;
		mbedtls_ssl_conf_cbc_record_splitting(ssl_config, stack->to<int>(1));
		return 0;
	}

	int SSLConfig::setSessionTickets(State & state, mbedtls_ssl_config * ssl_config){
		Stack * stack = state.stack;
		mbedtls_ssl_conf_session_tickets(ssl_config, stack->to<int>(1));
		return 0;
	}

	int SSLConfig::setRenegotiation(State & state, mbedtls_ssl_config * ssl_config){
		Stack * stack = state.stack;
		mbedtls_ssl_conf_renegotiation(ssl_config, stack->to<int>(1));
		return 0;
	}

	int SSLConfig::setLegacyRenegotiation(State & state, mbedtls_ssl_config * ssl_config){
		Stack * stack = state.stack;
		mbedtls_ssl_conf_legacy_renegotiation(ssl_config, stack->to<int>(1));
		return 0;
	}

	int SSLConfig::setRenegotiationEnforced(State & state, mbedtls_ssl_config * ssl_config){
		Stack * stack = state.stack;
		mbedtls_ssl_conf_renegotiation_enforced(ssl_config, stack->to<int>(1));
		return 0;
	}

	int SSLConfig::setRenegotiationPeriod(State & state, mbedtls_ssl_config * ssl_config){
		Stack * stack = state.stack;
		
		unsigned char period[8];
		uint64_t * _period = reinterpret_cast<unsigned long long *>(period);
		*_period = stack->to<int>(1) & 0xFFFFFFFF;
		*_period |= static_cast<uint64_t>((stack->to<int>(2) & 0xFFFFFFFF)) << 32;

		mbedtls_ssl_conf_renegotiation_period(ssl_config, period);
		return 0;
	}

	int SSLConfig::setRNG(State & state, mbedtls_ssl_config * ssl_config){
		Stack * stack = state.stack;
		CTRDRBGContext * interfaceCTRDRBGContext = OBJECT_IFACE(CTRDRBGContext);
		mbedtls_ctr_drbg_context * context = interfaceCTRDRBGContext->get(1);
		if (context){
			mbedtls_ssl_conf_rng(ssl_config, mbedtls_ctr_drbg_random, context);
		}
		return 0;
	}

	void SSLConfig::debugCallback(void * context, int level, const char * file, int line, const char * str){
		fprintf(stderr, "(%d) %s:%04d: %s", level, file, line, str);
		fflush(stderr);
	}

	int SSLConfig::setDBG(State & state, mbedtls_ssl_config * ssl_config){
		Stack * stack = state.stack;
		bool enabled = stack->to<bool>(1);

		if (enabled){
			mbedtls_ssl_conf_dbg(ssl_config, debugCallback, nullptr);
		}
		else{
			mbedtls_ssl_conf_dbg(ssl_config, nullptr, nullptr);
		}
		return 0;
	}


	void initSSLConfig(State * state, Module & module){
		INIT_OBJECT(SSLConfig);
	}
};
