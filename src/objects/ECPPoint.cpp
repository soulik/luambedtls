#include "objects/ECPPoint.hpp"
#include "objects/ECPGroup.hpp"
#include "objects/MPI.hpp"

namespace luambedtls {
	mbedtls_ecp_point * ECPPoint::constructor(State & state, bool & managed){
		mbedtls_ecp_point * point = new mbedtls_ecp_point;
		mbedtls_ecp_point_init(point);
		return point;
	}

	void ECPPoint::destructor(State & state, mbedtls_ecp_point * point){
		mbedtls_ecp_point_free(point);
		delete point;
	}

	int ECPPoint::getX(State & state, mbedtls_ecp_point * point){
		Stack * stack = state.stack;
		MPI * interfaceMPI = OBJECT_IFACE(MPI);
		interfaceMPI->push(&point->X);
		return 1;
	}
	int ECPPoint::getY(State & state, mbedtls_ecp_point * point){
		Stack * stack = state.stack;
		MPI * interfaceMPI = OBJECT_IFACE(MPI);
		interfaceMPI->push(&point->X);
		return 1;
	}
	int ECPPoint::getZ(State & state, mbedtls_ecp_point * point){
		Stack * stack = state.stack;
		MPI * interfaceMPI = OBJECT_IFACE(MPI);
		interfaceMPI->push(&point->X);
		return 1;
	}

	int ECPPoint::setX(State & state, mbedtls_ecp_point * point){
		Stack * stack = state.stack;
		MPI * interfaceMPI = OBJECT_IFACE(MPI);
		mbedtls_mpi * other = interfaceMPI->get(1);
		if (other){
			mbedtls_mpi_copy(&point->X, other);
		}
		return 0;
	}
	int ECPPoint::setY(State & state, mbedtls_ecp_point * point){
		Stack * stack = state.stack;
		MPI * interfaceMPI = OBJECT_IFACE(MPI);
		mbedtls_mpi * other = interfaceMPI->get(1);
		if (other){
			mbedtls_mpi_copy(&point->Y, other);
		}
		return 0;
	}
	int ECPPoint::setZ(State & state, mbedtls_ecp_point * point){
		Stack * stack = state.stack;
		MPI * interfaceMPI = OBJECT_IFACE(MPI);
		mbedtls_mpi * other = interfaceMPI->get(1);
		if (other){
			mbedtls_mpi_copy(&point->Z, other);
		}
		return 0;
	}

	int ECPPoint::copy(State & state, mbedtls_ecp_point * point){
		Stack * stack = state.stack;
		ECPPoint * interfaceECPPoint = OBJECT_IFACE(ECPPoint);
		mbedtls_ecp_point * src = interfaceECPPoint->get(1);
		if (src){
			stack->push<int>(mbedtls_ecp_copy(point, src));
			return 1;
		}
		return 0;
	}

	int ECPPoint::zero(State & state, mbedtls_ecp_point * point){
		Stack * stack = state.stack;
		stack->push<int>(mbedtls_ecp_set_zero(point));
		return 1;
	}

	int ECPPoint::isZero(State & state, mbedtls_ecp_point * point){
		Stack * stack = state.stack;
		stack->push<bool>(mbedtls_ecp_is_zero(point) == 0);
		return 1;
	}

	int ECPPoint::readString(State & state, mbedtls_ecp_point * point){
		Stack * stack = state.stack;
		if (stack->is<LUA_TNUMBER>(1) && stack->is<LUA_TSTRING>(2) && stack->is<LUA_TSTRING>(3)){
			int radix = stack->to<int>(1);
			const std::string value1 = stack->to<const std::string>(2);
			const std::string value2 = stack->to<const std::string>(3);
			stack->push<int>(mbedtls_ecp_point_read_string(point, radix, value1.c_str(), value2.c_str()));
			return 1;
		}
		return 0;
	}
	int ECPPoint::readBinary(State & state, mbedtls_ecp_point * point){
		Stack * stack = state.stack;
		ECPGroup * interfaceECPGroup = OBJECT_IFACE(ECPGroup);
		mbedtls_ecp_group * group = interfaceECPGroup->get(1);
		if (group && stack->is<LUA_TSTRING>(2)){
			const std::string value = stack->toLString(2);
			stack->push<int>(mbedtls_ecp_point_read_binary(group, point, reinterpret_cast<const unsigned char*>(value.c_str()), value.length()));
			return 1;
		}
		return 0;
	}
	int ECPPoint::writeBinary(State & state, mbedtls_ecp_point * point){
		Stack * stack = state.stack;
		ECPGroup * interfaceECPGroup = OBJECT_IFACE(ECPGroup);
		mbedtls_ecp_group * group = interfaceECPGroup->get(1);
		if (group && stack->is<LUA_TNUMBER>(2) && stack->is<LUA_TNUMBER>(3)){
			int format = stack->to<int>(2);
			const size_t outputMaxLength = stack->to<int>(3);
			size_t outputLength = 0;
			unsigned char * buffer = new unsigned char[outputMaxLength];
			int result = mbedtls_ecp_point_write_binary(group, point, format, &outputLength, buffer, outputMaxLength);
			if (result == 0){
				stack->pushLString(std::string(reinterpret_cast<char *>(buffer), outputLength));
			}
			else{
				stack->push<int>(result);
			}
			return 1;
		}
		return 0;
	}

	int ECPPoint::read(State & state, mbedtls_ecp_point * point){
		Stack * stack = state.stack;
		ECPGroup * interfaceECPGroup = OBJECT_IFACE(ECPGroup);
		mbedtls_ecp_group * group = interfaceECPGroup->get(1);
		if (group && stack->is<LUA_TSTRING>(2)){
			const std::string value = stack->toLString(2);
			const unsigned char* input = reinterpret_cast<const unsigned char*>(value.c_str());
			stack->push<int>(mbedtls_ecp_tls_read_point(group, point, &input, value.length()));
			return 1;
		}
		return 0;
	}

	int ECPPoint::write(State & state, mbedtls_ecp_point * point){
		Stack * stack = state.stack;
		ECPGroup * interfaceECPGroup = OBJECT_IFACE(ECPGroup);
		mbedtls_ecp_group * group = interfaceECPGroup->get(1);
		if (group && stack->is<LUA_TNUMBER>(2) && stack->is<LUA_TNUMBER>(3)){
			int format = stack->to<int>(2);
			const size_t outputMaxLength = stack->to<int>(3);
			size_t outputLength = 0;
			unsigned char * buffer = new unsigned char[outputMaxLength];
			int result = mbedtls_ecp_tls_write_point(group, point, format, &outputLength, buffer, outputMaxLength);
			if (result == 0){
				stack->pushLString(std::string(reinterpret_cast<char *>(buffer), outputLength));
			}
			else{
				stack->push<int>(result);
			}
			return 1;
		}
		return 0;
	}



	void initECPPoint(State * state, Module & module){
		INIT_OBJECT(ECPPoint);
	}
};
