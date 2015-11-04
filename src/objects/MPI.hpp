#ifndef LUA_MBEDTLS_OBJECTS_MPI_H
#define LUA_MBEDTLS_OBJECTS_MPI_H

#include "common.hpp"

namespace luambedtls {
	class MPI : public Object<mbedtls_mpi> {
	public:
		explicit MPI(State * state) : Object<mbedtls_mpi>(state){
			LUTOK_PROPERTY("bitLen", &MPI::getBitLen, &MPI::nullMethod);
			LUTOK_PROPERTY("size", &MPI::getSize, &MPI::nullMethod);
			LUTOK_PROPERTY("LSB", &MPI::getLSB, &MPI::nullMethod);

			LUTOK_METHOD("grow", &MPI::grow);
			LUTOK_METHOD("grow", &MPI::grow);
			LUTOK_METHOD("grow", &MPI::grow);
			LUTOK_METHOD("shrink", &MPI::shrink);
			LUTOK_METHOD("copy", &MPI::copy);
			LUTOK_METHOD("swap", &MPI::swap);
			LUTOK_METHOD("safeCondAssign", &MPI::safeCondAssign);
			LUTOK_METHOD("safeCondSwap", &MPI::safeCondSwap);
			LUTOK_METHOD("getBit", &MPI::getBit);
			LUTOK_METHOD("setBit", &MPI::setBit);

			LUTOK_METHOD("readString", &MPI::readString);
			LUTOK_METHOD("writeString", &MPI::writeString);
			LUTOK_METHOD("readFile", &MPI::readFile);
			LUTOK_METHOD("writeFile", &MPI::writeFile);
			LUTOK_METHOD("readBinary", &MPI::readBinary);
			LUTOK_METHOD("writeBinary", &MPI::writeBinary);

			LUTOK_METHOD("shiftL", &MPI::shiftL);
			LUTOK_METHOD("shiftR", &MPI::shiftR);
			LUTOK_METHOD("cmpAbs", &MPI::cmpAbs);
			LUTOK_METHOD("cmpMPI", &MPI::cmpMPI);
			LUTOK_METHOD("cmpInt", &MPI::cmpInt);
			LUTOK_METHOD("addAbs", &MPI::addAbs);
			LUTOK_METHOD("subAbs", &MPI::subAbs);
			LUTOK_METHOD("addMPI", &MPI::addMPI);
			LUTOK_METHOD("subMPI", &MPI::subMPI);
			LUTOK_METHOD("addInt", &MPI::addInt);
			LUTOK_METHOD("subInt", &MPI::subInt);
			LUTOK_METHOD("mulMPI", &MPI::mulMPI);
			LUTOK_METHOD("mulInt", &MPI::mulInt);
			LUTOK_METHOD("divMPI", &MPI::divMPI);
			LUTOK_METHOD("divInt", &MPI::divInt);
			LUTOK_METHOD("modMPI", &MPI::modMPI);
			LUTOK_METHOD("modInt", &MPI::modInt);
			LUTOK_METHOD("expMod", &MPI::expMod);
			LUTOK_METHOD("fillRandom", &MPI::fillRandom);
			LUTOK_METHOD("GCD", &MPI::GCD);
			LUTOK_METHOD("invMod", &MPI::invMod);
			LUTOK_METHOD("isPrime", &MPI::isPrime);
			LUTOK_METHOD("genPrime", &MPI::genPrime);
		}

		mbedtls_mpi * constructor(State & state, bool & managed);

		void destructor(State & state, mbedtls_mpi * mpi);

		int grow(State & state, mbedtls_mpi * mpi);
		int shrink(State & state, mbedtls_mpi * mpi);
		int copy(State & state, mbedtls_mpi * mpi);
		int swap(State & state, mbedtls_mpi * mpi);
		int safeCondAssign(State & state, mbedtls_mpi * mpi);
		int safeCondSwap(State & state, mbedtls_mpi * mpi);
		int lset(State & state, mbedtls_mpi * mpi);
		int getBit(State & state, mbedtls_mpi * mpi);
		int setBit(State & state, mbedtls_mpi * mpi);
		int getLSB(State & state, mbedtls_mpi * mpi);
		int getBitLen(State & state, mbedtls_mpi * mpi);
		int getSize(State & state, mbedtls_mpi * mpi);

		int readString(State & state, mbedtls_mpi * mpi);
		int writeString(State & state, mbedtls_mpi * mpi);
		int readFile(State & state, mbedtls_mpi * mpi);
		int writeFile(State & state, mbedtls_mpi * mpi);
		int readBinary(State & state, mbedtls_mpi * mpi);
		int writeBinary(State & state, mbedtls_mpi * mpi);

		int shiftL(State & state, mbedtls_mpi * mpi);
		int shiftR(State & state, mbedtls_mpi * mpi);
		int cmpAbs(State & state, mbedtls_mpi * mpi);
		int cmpMPI(State & state, mbedtls_mpi * mpi);
		int cmpInt(State & state, mbedtls_mpi * mpi);
		int addAbs(State & state, mbedtls_mpi * mpi);
		int subAbs(State & state, mbedtls_mpi * mpi);
		int addMPI(State & state, mbedtls_mpi * mpi);
		int subMPI(State & state, mbedtls_mpi * mpi);
		int addInt(State & state, mbedtls_mpi * mpi);
		int subInt(State & state, mbedtls_mpi * mpi);
		int mulMPI(State & state, mbedtls_mpi * mpi);
		int mulInt(State & state, mbedtls_mpi * mpi);
		int divMPI(State & state, mbedtls_mpi * mpi);
		int divInt(State & state, mbedtls_mpi * mpi);
		int modMPI(State & state, mbedtls_mpi * mpi);
		int modInt(State & state, mbedtls_mpi * mpi);
		int expMod(State & state, mbedtls_mpi * mpi);
		int fillRandom(State & state, mbedtls_mpi * mpi);
		int GCD(State & state, mbedtls_mpi * mpi);
		int invMod(State & state, mbedtls_mpi * mpi);
		int isPrime(State & state, mbedtls_mpi * mpi);
		int genPrime(State & state, mbedtls_mpi * mpi);

		int operator_tostring(State & state, mbedtls_mpi * mpi);
	};
	void initMPI(State*, Module&);
	int MPISelfTest(State&);
};
#endif	
