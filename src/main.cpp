/*
	luambedtls - Lua binding for mbedtls library

	Copyright 2015 Mário Kašuba

	All rights reserved.

	Redistribution and use in source and binary forms, with or without
	modification, are permitted provided that the following conditions are
	met:

	* Redistributions of source code must retain the above copyright
	  notice, this list of conditions and the following disclaimer.
	* Redistributions in binary form must reproduce the above copyright
	  notice, this list of conditions and the following disclaimer in the
	  documentation and/or other materials provided with the distribution.

	THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
	"AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
	LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
	A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
	OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
	SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
	LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
	DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
	THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
	(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
	OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

*/

#include "common.hpp"
#include "main.hpp"
#include "init_classes.hpp"
#include "utils.hpp"

namespace luambedtls {
	int init(State & state){

		return 0;
	}

	static int strError(State & state){
		Stack * stack = state.stack;
		char buffer[1024];
		mbedtls_strerror(stack->to<int>(1), buffer, 1024);
		stack->push<const std::string &>(buffer);
		return 1;
	}

	static int debugTreshhold(State & state){
		Stack * stack = state.stack;
		mbedtls_debug_set_threshold(stack->to<int>(1));
		return 0;
	}

	extern "C" LUAMBEDTLS_DLL_EXPORTED int luaopen_luambedtls(lua_State * L){
		State * state = new State(L);
		Stack * stack = state->stack;
		Module luambedtls_module;

		stack->newTable();

		initMPI(state, luambedtls_module);
		initASN1buf(state, luambedtls_module);
		initASN1named(state, luambedtls_module);
		initASN1sequence(state, luambedtls_module);

		//key-pairs
		initPKContext(state, luambedtls_module);
		initPKinfo(state, luambedtls_module);

		initCTRDRBGContext(state, luambedtls_module);
		initDHMContext(state, luambedtls_module);
		initEntropyContext(state, luambedtls_module);
		initSSLConfig(state, luambedtls_module);
		initSSLContext(state, luambedtls_module);
		initSSLCookieContext(state, luambedtls_module);
		initSSLSession(state, luambedtls_module);
		initx509crt(state, luambedtls_module);
		initx509crl(state, luambedtls_module);
		initx509crlEntry(state, luambedtls_module);
		initx509crtProfile(state, luambedtls_module);
		initx509csr(state, luambedtls_module);
		initx509writeCert(state, luambedtls_module);
		initx509writeCSR(state, luambedtls_module);
		initTimingDelayContext(state, luambedtls_module);
		initAESContext(state, luambedtls_module);

		//symmetric-encryption
		initARC4Context(state, luambedtls_module);
		initBlowfishContext(state, luambedtls_module);
		initCamelliaContext(state, luambedtls_module);
		initDESContext(state, luambedtls_module);
		initDES3Context(state, luambedtls_module);
		initGCMContext(state, luambedtls_module);
		initXTEAContext(state, luambedtls_module);

		//asymmetric-ecnryption
		initDHMContext(state, luambedtls_module);
		initRSAContext(state, luambedtls_module);

		//EC
		initECPCurveInfo(state, luambedtls_module);
		initECPPoint(state, luambedtls_module);
		initECPGroup(state, luambedtls_module);
		initECPKeyPair(state, luambedtls_module);
		initECDHContext(state, luambedtls_module);
		initECSDAContext(state, luambedtls_module);

		//message-digest
		initMDContext(state, luambedtls_module);
		initMDinfo(state, luambedtls_module);

		//cipher
		initCipherContext(state, luambedtls_module);
		initCipherInfo(state, luambedtls_module);

		//utils
		initUtils(state, luambedtls_module);

		luambedtls_module["init"] = init;
		initConstants(state, luambedtls_module);
		luambedtls_module["strError"] = strError;
		luambedtls_module["debugTreshhold"] = debugTreshhold;
		luambedtls_module["MPIlen"] = MPIlen;
		luambedtls_module["pushOIDAttrShortName"] = pushOIDAttrShortName;
		luambedtls_module["pushOIDNumericString"] = pushOIDNumericString;
		luambedtls_module["pushOIDExtType"] = pushOIDExtType;
		luambedtls_module["pushOIDPkAlg"] = pushOIDPkAlg;

		state->registerLib(luambedtls_module);
		return 1;
	}

};
