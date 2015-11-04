#ifndef LUA_MBEDTLS_OBJECTS_ECPPOINT_H
#define LUA_MBEDTLS_OBJECTS_ECPPOINT_H

#include "common.hpp"

namespace luambedtls {
	class ECPPoint : public Object<mbedtls_ecp_point> {
	public:
		explicit ECPPoint(State * state) : Object<mbedtls_ecp_point>(state){
			LUTOK_PROPERTY("x", &ECPPoint::getX, &ECPPoint::setX);
			LUTOK_PROPERTY("y", &ECPPoint::getY, &ECPPoint::setY);
			LUTOK_PROPERTY("z", &ECPPoint::getZ, &ECPPoint::setZ);
			LUTOK_PROPERTY("isZero", &ECPPoint::isZero, &ECPPoint::nullMethod);

			LUTOK_METHOD("copy", &ECPPoint::copy);
			LUTOK_METHOD("zero", &ECPPoint::zero);

			LUTOK_METHOD("readString", &ECPPoint::readString);
			LUTOK_METHOD("readBinary", &ECPPoint::readBinary);
			LUTOK_METHOD("writeBinary", &ECPPoint::writeBinary);

			LUTOK_METHOD("read", &ECPPoint::read);
			LUTOK_METHOD("write", &ECPPoint::write);
		}

		mbedtls_ecp_point * constructor(State & state, bool & managed);

		void destructor(State & state, mbedtls_ecp_point * point);

		int copy(State & state, mbedtls_ecp_point * point);
		int zero(State & state, mbedtls_ecp_point * point);
		int isZero(State & state, mbedtls_ecp_point * point);

		int readString(State & state, mbedtls_ecp_point * point);
		int readBinary(State & state, mbedtls_ecp_point * point);
		int writeBinary(State & state, mbedtls_ecp_point * point);
		int read(State & state, mbedtls_ecp_point * point);
		int write(State & state, mbedtls_ecp_point * point);

		int getX(State & state, mbedtls_ecp_point * point);
		int getY(State & state, mbedtls_ecp_point * point);
		int getZ(State & state, mbedtls_ecp_point * point);

		int setX(State & state, mbedtls_ecp_point * point);
		int setY(State & state, mbedtls_ecp_point * point);
		int setZ(State & state, mbedtls_ecp_point * point);

	};
	void initECPPoint(State*, Module&);
};
#endif	
