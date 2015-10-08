#ifndef LUA_MBEDTLS_OBJECTS_MDINFO_H
#define LUA_MBEDTLS_OBJECTS_MDINFO_H

#include "common.hpp"

namespace luambedtls {
	class MDinfo : public Object<mbedtls_md_info_t> {
	public:
		explicit MDinfo(State * state) : Object<mbedtls_md_info_t>(state){
			LUTOK_PROPERTY("blockSize", &MDinfo::getBlockSize, &MDinfo::nullMethod);
			LUTOK_PROPERTY("size", &MDinfo::getSize, &MDinfo::nullMethod);
			LUTOK_PROPERTY("type", &MDinfo::getType, &MDinfo::nullMethod);
			LUTOK_PROPERTY("name", &MDinfo::getName, &MDinfo::nullMethod);

			LUTOK_METHOD("md", &MDinfo::md);
			LUTOK_METHOD("mdHMAC", &MDinfo::mdHMAC);
		}

		mbedtls_md_info_t * constructor(State & state, bool & managed);

		void destructor(State & state, mbedtls_md_info_t * object);

		int getBlockSize(State & state, mbedtls_md_info_t * object);
		int getSize(State & state, mbedtls_md_info_t * object);
		int getType(State & state, mbedtls_md_info_t * object);
		int getName(State & state, mbedtls_md_info_t * object);

		int md(State & state, mbedtls_md_info_t * object);
		int mdHMAC(State & state, mbedtls_md_info_t * object);
	};
};

#endif	
