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

#ifndef LUA_MBEDTLS_COMMON_H
#define LUA_MBEDTLS_COMMON_H

#include <lutok2/lutok2.hpp>
using namespace lutok2;

#if (BUILDING_LUAMBEDTLS || luambedtls_EXPORTS) && HAVE_VISIBILITY
#define LUAMBEDTLS_DLL_EXPORTED __attribute__((visibility("default")))
#elif (BUILDING_LUAMBEDTLS || luambedtls_EXPORTS) && defined _MSC_VER
#define LUAMBEDTLS_DLL_EXPORTED __declspec(dllexport)
#elif defined _MSC_VER
#define LUAMBEDTLS_DLL_EXPORTED __declspec(dllimport)
#else
#define LUAMBEDTLS_DLL_EXPORTED
#endif

#define INIT_OBJECT(OBJ_NAME) state->registerInterface<OBJ_NAME>("luambedtls_" #OBJ_NAME); state->stack->setField(#OBJ_NAME)
#define OBJECT_IFACE(OBJ_NAME) state.getInterface<OBJ_NAME>("luambedtls_" #OBJ_NAME)

#include <mbedtls/aes.h>
#include <mbedtls/arc4.h>
#include <mbedtls/blowfish.h>
#include <mbedtls/camellia.h>
#include <mbedtls/des.h>
#include <mbedtls/gcm.h>
#include <mbedtls/xtea.h>

#include <mbedtls/md.h>
#include <mbedtls/md_internal.h>

#include <mbedtls/dhm.h>
#include <mbedtls/rsa.h>
#include <mbedtls/ecp.h>
#include <mbedtls/ecdsa.h>
#include <mbedtls/ecdh.h>

#include <mbedtls/ssl.h>
#include <mbedtls/ssl_cookie.h>
#include <mbedtls/entropy.h>
#include <mbedtls/x509.h>
#include <mbedtls/x509_csr.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/certs.h>
#include <mbedtls/timing.h>
#include <mbedtls/error.h>
#include <mbedtls/debug.h>

#include <mbedtls/oid.h>
#include <mbedtls/pk.h>
#include <mbedtls/pk_internal.h>

#include <mbedtls/cipher.h>
#include <mbedtls/cipher_internal.h>

#include <mbedtls/base64.h>

namespace luambedtls {
	int pushMPI(Stack * stack, const mbedtls_mpi * X, int radix = 16);
	int readMPI(Stack * stack, mbedtls_mpi * X, int radix = 16, const int index = -1);
	int MPIlen(State & state);
	int pushX509time(State & state, mbedtls_x509_time * t);

};

#endif
