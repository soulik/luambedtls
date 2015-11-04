#ifndef LUA_MBEDTLS_OBJECTS_PKINFO_H
#define LUA_MBEDTLS_OBJECTS_PKINFO_H

#include "common.hpp"

namespace luambedtls {
	class PKinfo : public Object<mbedtls_pk_info_t> {
	public:
		explicit PKinfo(State * state) : Object<mbedtls_pk_info_t>(state){
			LUTOK_PROPERTY("type", &PKinfo::getType, &PKinfo::nullMethod);
			LUTOK_PROPERTY("name", &PKinfo::getName, &PKinfo::nullMethod);
		}

		mbedtls_pk_info_t * constructor(State & state, bool & managed);

		void destructor(State & state, mbedtls_pk_info_t * info);

		int getType(State & state, mbedtls_pk_info_t * info);
		int getName(State & state, mbedtls_pk_info_t * info);
	};
	void initPKinfo(State*, Module&);
	int PKinfoFromType(State&);
};
#endif	
