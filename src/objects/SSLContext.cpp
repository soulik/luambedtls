#include "objects/SSLContext.hpp"
#include "objects/SSLConfig.hpp"
#include "objects/SSLSession.hpp"
#include "objects/x509crt.hpp"
#include "objects/x509crl.hpp"
#include "objects/x509crtProfile.hpp"
#include "objects/PKContext.hpp"
#include "objects/TimingDelayContext.hpp"
#include <string.h>

namespace luambedtls {
	SSLContextData * SSLContext::constructor(State & state, bool & managed){
		SSLContextData * ssl_context_data = new SSLContextData;
		ssl_context_data->context = new mbedtls_ssl_context;
		ssl_context_data->state = &state;
		ssl_context_data->recvRef = LUA_REFNIL;
		ssl_context_data->recvTimeoutRef = LUA_REFNIL;
		ssl_context_data->sendRef = LUA_REFNIL;
		memset(ssl_context_data->context, 0, sizeof(mbedtls_ssl_context));
		mbedtls_ssl_init(ssl_context_data->context);
		return ssl_context_data;
	}

	void SSLContext::destructor(State & state, SSLContextData * ssl_context_data){
		Stack * stack = state.stack;
		if (ssl_context_data->sendRef != LUA_REFNIL){
			stack->unref(ssl_context_data->sendRef);
		}
		if (ssl_context_data->recvRef != LUA_REFNIL){
			stack->unref(ssl_context_data->recvRef);
		}
		if (ssl_context_data->recvTimeoutRef != LUA_REFNIL){
			stack->unref(ssl_context_data->recvTimeoutRef);
		}

		ssl_context_data->sendRef = LUA_REFNIL;
		ssl_context_data->recvRef = LUA_REFNIL;
		ssl_context_data->recvTimeoutRef = LUA_REFNIL;

		mbedtls_ssl_free(ssl_context_data->context);
		//ssl_context_data->context->conf->f_dbg
		delete ssl_context_data->context;
		delete ssl_context_data;
	}

	int SSLContext::setup(State & state, SSLContextData * ssl_context_data){
		Stack * stack = state.stack;
		SSLConfig * interfaceSSLConfig = OBJECT_IFACE(SSLConfig);
		mbedtls_ssl_config * ssl_config = interfaceSSLConfig->get(1);
		if (ssl_config){
			stack->push<int>(mbedtls_ssl_setup(ssl_context_data->context, ssl_config));
			return 1;
		}
		return 0;
	}

	int SSLContext::sessionReset(State & state, SSLContextData * ssl_context_data){
		Stack * stack = state.stack;
		stack->push<int>(mbedtls_ssl_session_reset(ssl_context_data->context));
		return 1;
	}

	int SSLContext::setClientTransportID(State & state, SSLContextData * ssl_context_data){
		Stack * stack = state.stack;
		if (stack->is<LUA_TSTRING>(1)){
			const std::string clientTransportID = stack->toLString(1);
			stack->push<int>(mbedtls_ssl_set_client_transport_id(ssl_context_data->context, reinterpret_cast<unsigned char *>(const_cast<char *>(clientTransportID.c_str())), clientTransportID.length()));
			return 1;
		}
		return 0;
	}

	int SSLContext::setSession(State & state, SSLContextData * ssl_context_data){
		Stack * stack = state.stack;
		SSLSession * interfaceSSLSession = OBJECT_IFACE(SSLSession);
		mbedtls_ssl_session * ssl_session = interfaceSSLSession->get(1);
		if (ssl_session){
			stack->push<int>(mbedtls_ssl_set_session(ssl_context_data->context, ssl_session));
			return 1;
		}
		return 0;
	}

	int SSLContext::setPSK(State & state, SSLContextData * ssl_context_data){
		Stack * stack = state.stack;
		if (stack->is<LUA_TSTRING>(1)){
			const std::string psk = stack->toLString(1);

			stack->push<int>(mbedtls_ssl_set_hs_psk(ssl_context_data->context, reinterpret_cast<const unsigned char*>(psk.c_str()), psk.length()));
			return 1;
		}
		return 0;
	}

	int SSLContext::setHostname(State & state, SSLContextData * ssl_context_data){
		Stack * stack = state.stack;
		if (stack->is<LUA_TSTRING>(1)){
			const std::string hostname = stack->to<const std::string>(1);

			stack->push<int>(mbedtls_ssl_set_hostname(ssl_context_data->context, hostname.c_str()));
			return 1;
		}
		return 0;
	}

	int SSLContext::setOwnCert(State & state, SSLContextData * ssl_context_data){
		Stack * stack = state.stack;
		x509crt * interfaceCert = OBJECT_IFACE(x509crt);
		PKContext * interfacePKContext = OBJECT_IFACE(PKContext);

		mbedtls_x509_crt * cert = interfaceCert->get(1);
		mbedtls_pk_context * PKcontext = interfacePKContext->get(1);

		if (cert && PKcontext){
			stack->push<int>(mbedtls_ssl_set_hs_own_cert(ssl_context_data->context, cert, PKcontext));
			return 1;
		}
		return 0;
	}

	int SSLContext::setCAChain(State & state, SSLContextData * ssl_context_data){
		Stack * stack = state.stack;
		x509crt * interfaceCert = OBJECT_IFACE(x509crt);
		x509crl * interfaceRevokeCert = OBJECT_IFACE(x509crl);
		mbedtls_x509_crt * cert = interfaceCert->get(1);
		mbedtls_x509_crl * revokeCert = interfaceRevokeCert->get(2);

		if (cert && revokeCert){
			mbedtls_ssl_set_hs_ca_chain(ssl_context_data->context, cert, revokeCert);
		}
		return 0;
	}

	int SSLContext::setAuthmode(State & state, SSLContextData * ssl_context_data){
		Stack * stack = state.stack;
		mbedtls_ssl_set_hs_authmode(ssl_context_data->context, stack->to<int>(1));
		return 0;
	}

	int SSLContext::getALPNProtocol(State & state, SSLContextData * ssl_context_data){
		Stack * stack = state.stack;
		stack->push<const std::string &>(mbedtls_ssl_get_alpn_protocol(ssl_context_data->context));
		return 1;
	}

	int SSLContext::getBytesAvail(State & state, SSLContextData * ssl_context_data){
		Stack * stack = state.stack;
		stack->push<int>(mbedtls_ssl_get_bytes_avail(ssl_context_data->context));
		return 1;
	}

	int SSLContext::getVerifyResult(State & state, SSLContextData * ssl_context_data){
		Stack * stack = state.stack;
		stack->push<int>(mbedtls_ssl_get_verify_result(ssl_context_data->context));
		return 1;
	}

	int SSLContext::getCipherSuite(State & state, SSLContextData * ssl_context_data){
		Stack * stack = state.stack;
		stack->push<const std::string &>(mbedtls_ssl_get_ciphersuite(ssl_context_data->context));
		return 1;
	}

	int SSLContext::getVersion(State & state, SSLContextData * ssl_context_data){
		Stack * stack = state.stack;
		stack->push<const std::string &>(mbedtls_ssl_get_version(ssl_context_data->context));
		return 1;
	}

	int SSLContext::getRecordExpansion(State & state, SSLContextData * ssl_context_data){
		Stack * stack = state.stack;
		stack->push<int>(mbedtls_ssl_get_record_expansion(ssl_context_data->context));
		return 1;
	}

	int SSLContext::getPeerCert(State & state, SSLContextData * ssl_context_data){
		Stack * stack = state.stack;
		x509crt * interfaceCert = OBJECT_IFACE(x509crt);

		interfaceCert->push(const_cast<mbedtls_x509_crt *>(mbedtls_ssl_get_peer_cert(ssl_context_data->context)));
		return 1;
	}

	int SSLContext::getSession(State & state, SSLContextData * ssl_context_data){
		Stack * stack = state.stack;
		SSLSession * interfaceSSLSession = OBJECT_IFACE(SSLSession);
		
		mbedtls_ssl_session * session = new  mbedtls_ssl_session;

		if (mbedtls_ssl_get_session(ssl_context_data->context, session) == 0){
			interfaceSSLSession->push(session, true);
			return 1;
		}
		else{
			delete session;
			return 0;
		}
	}

	int SSLContext::handshake(State & state, SSLContextData * ssl_context_data){
		Stack * stack = state.stack;
		stack->push<int>(mbedtls_ssl_handshake(ssl_context_data->context));
		return 1;
	}

	int SSLContext::handshakeStep(State & state, SSLContextData * ssl_context_data){
		Stack * stack = state.stack;
		stack->push<int>(mbedtls_ssl_handshake_step(ssl_context_data->context));
		return 1;
	}

	int SSLContext::renegotiate(State & state, SSLContextData * ssl_context_data){
		Stack * stack = state.stack;
		stack->push<int>(mbedtls_ssl_renegotiate(ssl_context_data->context));
		return 1;
	}

	int SSLContext::read(State & state, SSLContextData * ssl_context_data){
		Stack * stack = state.stack;
		int maxLength = stack->to<int>(1);
		unsigned char * buffer = new unsigned char[maxLength];

		int result = mbedtls_ssl_read(ssl_context_data->context, buffer, maxLength);
		if (result > 0){
			stack->push<int>(result);
			stack->pushLString(std::string(reinterpret_cast<char*>(buffer), result));
			delete[] buffer;
			return 2;
		}
		else{
			if (result == 0){
				stack->push<int>(0);
				stack->pushLString(std::string(reinterpret_cast<char*>(buffer), result));
				delete[] buffer;
				return 2;
			}
			else{
				stack->push<int>(result);
				delete[] buffer;
				return 1;
			}
		}
	}

	int SSLContext::write(State & state, SSLContextData * ssl_context_data){
		Stack * stack = state.stack;
		if (stack->is<LUA_TSTRING>(1)){
			const std::string buffer = stack->toLString(1);
			int result = mbedtls_ssl_write(ssl_context_data->context, reinterpret_cast<const unsigned char *>(buffer.c_str()), buffer.length());

			stack->push<int>(result);
			return 1;
		}
		else{
			return 0;
		}
	}

	int SSLContext::sendAlertMessage(State & state, SSLContextData * ssl_context_data){
		Stack * stack = state.stack;
		stack->push<int>(mbedtls_ssl_send_alert_message(ssl_context_data->context, stack->to<int>(1), stack->to<int>(2)));
		return 1;
	}

	int SSLContext::closeNotify(State & state, SSLContextData * ssl_context_data){
		Stack * stack = state.stack;
		stack->push<int>(mbedtls_ssl_close_notify(ssl_context_data->context));
		return 1;
	}

	int SSLContext::recvCallback(void * context_data, unsigned char * data, size_t len){
		SSLContextData * ssl_context_data = reinterpret_cast<SSLContextData *>(context_data);
		if (ssl_context_data && ssl_context_data->state && ssl_context_data->recvRef != LUA_REFNIL) {
			State * state = ssl_context_data->state;
			Stack * stack = state->stack;
			stack->regValue(ssl_context_data->recvRef);
			if (stack->is<LUA_TFUNCTION>(-1)){
				stack->push<int>(len);
				stack->call(1, 2);

				int result = stack->to<int>(-1);
				if (stack->is<LUA_TSTRING>(-2)){
					const std::string buffer = stack->toLString(-2);
					size_t bufferLength = buffer.length();
					memcpy(data, buffer.c_str(), (bufferLength <= len) ? bufferLength : len);
				}
				stack->pop(2);
				return result;
			}
			else{
				return 0;
			}
		}
		else{
			return 0;
		}
	}

	int SSLContext::recvTimeoutCallback(void * context_data, unsigned char * data, size_t len, uint32_t t){
		SSLContextData * ssl_context_data = reinterpret_cast<SSLContextData *>(context_data);
		if (ssl_context_data && ssl_context_data->state && ssl_context_data->recvTimeoutRef != LUA_REFNIL) {
			State * state = ssl_context_data->state;
			Stack * stack = state->stack;
			stack->regValue(ssl_context_data->recvTimeoutRef);
			if (stack->is<LUA_TFUNCTION>(-1)){
				stack->push<int>(len);
				stack->push<int>(t);
				stack->call(2, 2);

				int result = stack->to<int>(-1);
				if (stack->is<LUA_TSTRING>(-2)){
					const std::string buffer = stack->toLString(-2);
					const char * bufferData = buffer.c_str();
					size_t bufferLength = buffer.length();
					memcpy(data, bufferData, (bufferLength <= len) ? bufferLength : len);
				}
				stack->pop(2);
				return result;
			}
			else{
				return 0;
			}
		}
		else{
			return 0;
		}
	}

	int SSLContext::sendCallback(void * context_data, const unsigned char * data, size_t len){
		SSLContextData * ssl_context_data = reinterpret_cast<SSLContextData *>(context_data);

		if (ssl_context_data && ssl_context_data->state && ssl_context_data->sendRef != LUA_REFNIL) {
			State * state = ssl_context_data->state;
			Stack * stack = state->stack;

			stack->regValue(ssl_context_data->sendRef);
			if (stack->is<LUA_TFUNCTION>(-1)){
				stack->pushLString(std::string(reinterpret_cast<const char *>(data), len));
				stack->push<int>(len);
				stack->call(2, 1);
				int result = stack->to<int>(-1);
				stack->pop(1);
				return result;
			}else{
				return 0;
			}
		}
		else{
			return 0;
		}
	}

	int SSLContext::setBIO(State & state, SSLContextData * ssl_context_data){
		Stack * stack = state.stack;
		
		if (stack->is<LUA_TFUNCTION>(1)){
			stack->pushValue(1);
			ssl_context_data->sendRef = stack->ref();
		}
		else{
			if (ssl_context_data->sendRef != LUA_REFNIL){
				stack->unref(ssl_context_data->sendRef);
			}
			ssl_context_data->sendRef = LUA_REFNIL;
		}

		if (stack->is<LUA_TFUNCTION>(2)){
			stack->pushValue(2);
			ssl_context_data->recvRef = stack->ref();
		}
		else{
			if (ssl_context_data->recvRef != LUA_REFNIL){
				stack->unref(ssl_context_data->recvRef);
			}
			ssl_context_data->recvRef = LUA_REFNIL;
		}

		if (stack->is<LUA_TFUNCTION>(3)){
			stack->pushValue(3);
			ssl_context_data->recvTimeoutRef = stack->ref();
		}
		else{
			if (ssl_context_data->recvTimeoutRef != LUA_REFNIL){
				stack->unref(ssl_context_data->recvTimeoutRef);
			}
			ssl_context_data->recvTimeoutRef = LUA_REFNIL;
		}

		mbedtls_ssl_set_bio(ssl_context_data->context, ssl_context_data, sendCallback, recvCallback, recvTimeoutCallback);
		return 0;
	}

	int SSLContext::setTimer(State & state, SSLContextData * ssl_context_data){
		Stack * stack = state.stack;
		TimingDelayContext * interfaceTimer = OBJECT_IFACE(TimingDelayContext);
		mbedtls_timing_delay_context * timer = interfaceTimer->get(1);
		if (timer){
			mbedtls_ssl_set_timer_cb(ssl_context_data->context, timer, mbedtls_timing_set_delay, mbedtls_timing_get_delay);
		}
		return 0;
	}

	static int lua_ciphersuites(State & state){
		Stack * stack = state.stack;
		const int * ids = mbedtls_ssl_list_ciphersuites();
		
		stack->newTable();

		while (*ids != 0){
			const char * name = mbedtls_ssl_get_ciphersuite_name(*ids);
			stack->setField<int>(name, *ids);
			ids++;
		}
		return 1;
	}

	void initSSLContext(State * state, Module & module){
		INIT_OBJECT(SSLContext);
		module["ciphersuites"] = lua_ciphersuites;
	}
};
