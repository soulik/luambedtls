#include "objects/PKinfo.hpp"

namespace luambedtls {
	mbedtls_pk_info_t * PKinfo::constructor(State & state, bool & managed){
		mbedtls_pk_info_t * info = new mbedtls_pk_info_t;
		return info;
	}

	void PKinfo::destructor(State & state, mbedtls_pk_info_t * info){
		delete info;
	}

	int PKinfo::getType(State & state, mbedtls_pk_info_t * info){
		Stack * stack = state.stack;
		stack->push<int>(info->type);
		return 1;
	}
	int PKinfo::getName(State & state, mbedtls_pk_info_t * info){
		Stack * stack = state.stack;
		stack->push<const std::string &>(info->name);
		return 1;
	}

	int PKinfoFromType(State & state){
		Stack * stack = state.stack;
		if (stack->is<LUA_TNUMBER>(1)){
			PKinfo * interfacePKinfo = OBJECT_IFACE(PKinfo);
			mbedtls_pk_type_t type = static_cast<mbedtls_pk_type_t>(stack->to<int>(1));
			const mbedtls_pk_info_t * info = mbedtls_pk_info_from_type(type);
			if (info){
				interfacePKinfo->push(const_cast<mbedtls_pk_info_t*>(info));
				return 1;
			}
		}
		return 0;
	}

	void initPKinfo(State * state, Module & module){
		INIT_OBJECT(PKinfo);
		module["PKinfoFromType"] = PKinfoFromType;
	}
};
