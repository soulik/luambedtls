#include "objects/MPI.hpp"
#include "objects/CTRDRBGContext.hpp"

namespace luambedtls {
	mbedtls_mpi * MPI::constructor(State & state, bool & managed){
		Stack * stack = state.stack;
		mbedtls_mpi * mpi = new mbedtls_mpi;
		mbedtls_mpi_init(mpi);

		if (stack->getTop() > 0){
			if (stack->is<LUA_TSTRING>(1)){
				const std::string str = stack->toLString(1);
				mbedtls_mpi_read_binary(mpi, reinterpret_cast<const unsigned char*>(str.c_str()), str.length());
			}
			else{
				MPI * interfaceMPI = OBJECT_IFACE(MPI);
				mbedtls_mpi * Y = interfaceMPI->get(1);
				if (Y){
					mbedtls_mpi_copy(mpi, Y);
				}
			}
		}
		return mpi;
	}

	void MPI::destructor(State & state, mbedtls_mpi * mpi){
		mbedtls_mpi_free(mpi);
		delete mpi;
	}

	int MPI::grow(State & state, mbedtls_mpi * mpi){
		Stack * stack = state.stack;
		if (stack->is<LUA_TNUMBER>(1)){
			stack->push<int>(mbedtls_mpi_grow(mpi, stack->to<int>(1)));
			return 1;
		}
		return 0;
	}
	int MPI::shrink(State & state, mbedtls_mpi * mpi){
		Stack * stack = state.stack;
		if (stack->is<LUA_TNUMBER>(1)){
			stack->push<int>(mbedtls_mpi_shrink(mpi, stack->to<int>(1)));
			return 1;
		}
		return 0;
	}
	int MPI::copy(State & state, mbedtls_mpi * mpi){
		Stack * stack = state.stack;
		MPI * interfaceMPI = OBJECT_IFACE(MPI);
		mbedtls_mpi * dest = interfaceMPI->get(1);
		if (dest){
			stack->push<int>(mbedtls_mpi_copy(dest, mpi));
			return 1;
		}
		return 0;
	}
	int MPI::swap(State & state, mbedtls_mpi * mpi){
		Stack * stack = state.stack;
		MPI * interfaceMPI = OBJECT_IFACE(MPI);
		mbedtls_mpi * dest = interfaceMPI->get(1);
		if (dest){
			mbedtls_mpi_swap(dest, mpi);
		}
		return 0;
	}
	int MPI::safeCondAssign(State & state, mbedtls_mpi * mpi){
		Stack * stack = state.stack;

		MPI * interfaceMPI = OBJECT_IFACE(MPI);
		mbedtls_mpi * dest = interfaceMPI->get(1);
		if (dest){
			unsigned char assign = 0;
			if (stack->is<LUA_TNUMBER>(2)){
				assign = stack->to<int>(2);
			}
			stack->push<int>(mbedtls_mpi_safe_cond_assign(dest, mpi, assign));
			return 1;
		}
		return 0;
	}
	int MPI::safeCondSwap(State & state, mbedtls_mpi * mpi){
		Stack * stack = state.stack;
		MPI * interfaceMPI = OBJECT_IFACE(MPI);
		mbedtls_mpi * dest = interfaceMPI->get(1);
		if (dest){
			unsigned char assign = 0;
			if (stack->is<LUA_TNUMBER>(2)){
				assign = stack->to<int>(2);
			}
			stack->push<int>(mbedtls_mpi_safe_cond_swap(dest, mpi, assign));
			return 1;
		}
		return 0;
	}
	int MPI::lset(State & state, mbedtls_mpi * mpi){
		Stack * stack = state.stack;
		if (stack->is<LUA_TNUMBER>(1)){
			mbedtls_mpi_sint z = stack->to<int>(1);
			stack->push<int>(mbedtls_mpi_lset(mpi, z));
			return 1;
		}
		return 0;
	}
	int MPI::getBit(State & state, mbedtls_mpi * mpi){
		Stack * stack = state.stack;
		if (stack->is<LUA_TNUMBER>(1)){
			size_t pos = stack->to<int>(1);
			stack->push<int>(mbedtls_mpi_get_bit(mpi, pos));
			return 1;
		}
		return 0;
	}
	int MPI::setBit(State & state, mbedtls_mpi * mpi){
		Stack * stack = state.stack;
		if (stack->is<LUA_TNUMBER>(1) && stack->is<LUA_TNUMBER>(2)){
			size_t pos = stack->to<int>(1);
			unsigned char value = stack->to<int>(2);
			stack->push<int>(mbedtls_mpi_set_bit(mpi, pos, value));
			return 1;
		}
		return 0;
	}
	int MPI::getLSB(State & state, mbedtls_mpi * mpi){
		Stack * stack = state.stack;
		stack->push<int>(mbedtls_mpi_lsb(mpi));
		return 1;
	}
	int MPI::getBitLen(State & state, mbedtls_mpi * mpi){
		Stack * stack = state.stack;
		stack->push<int>(mbedtls_mpi_bitlen(mpi));
		return 1;
	}
	int MPI::getSize(State & state, mbedtls_mpi * mpi){
		Stack * stack = state.stack;
		stack->push<int>(mbedtls_mpi_size(mpi));
		return 1;
	}

	int MPI::readString(State & state, mbedtls_mpi * mpi){
		Stack * stack = state.stack;
		if (stack->is<LUA_TNUMBER>(1) && stack->is<LUA_TSTRING>(2)){
			int radix = stack->to<int>(1);
			const std::string str = stack->to<const std::string>(2);
			stack->push<int>(mbedtls_mpi_read_string(mpi, radix, str.c_str()));
			return 1;
		}
		return 0;
	}
	int MPI::writeString(State & state, mbedtls_mpi * mpi){
		Stack * stack = state.stack;
		if (stack->is<LUA_TNUMBER>(1)){
			int radix = stack->to<int>(1);
			size_t length = 0;
			if (stack->is < LUA_TNUMBER>(2)){
				length = stack->to<int>(2);
			}
			else{
				mbedtls_mpi_write_string(mpi, radix, nullptr, 0, &length); //get minimum buffer length
			}

			char * output = new char[length];
			int result = mbedtls_mpi_write_string(mpi, radix, output, length, &length);
			if (result == 0){
				stack->push<const std::string &>(output);
			}
			else{
				stack->push<int>(result);
			}
			delete[] output;
			return 1;
		}
		return 0;
	}
	int MPI::readFile(State & state, mbedtls_mpi * mpi){
		Stack * stack = state.stack;
		return 0;
	}
	int MPI::writeFile(State & state, mbedtls_mpi * mpi){
		Stack * stack = state.stack;
		return 0;
	}
	int MPI::readBinary(State & state, mbedtls_mpi * mpi){
		Stack * stack = state.stack;
		if (stack->is<LUA_TSTRING>(1)){
			const std::string str = stack->toLString(1);
			stack->push<int>(mbedtls_mpi_read_binary(mpi, reinterpret_cast<const unsigned char*>(str.c_str()), str.length()));
			return 1;
		}
		return 0;
	}
	int MPI::writeBinary(State & state, mbedtls_mpi * mpi){
		Stack * stack = state.stack;
		if (stack->is<LUA_TNUMBER>(1)){
			size_t length = stack->to<int>(1);
			unsigned char * output = new unsigned char[length];

			int result = mbedtls_mpi_write_binary(mpi, output, length);
			if (result == 0){
				stack->pushLString(std::string(reinterpret_cast<char*>(output), length));
			}
			else{
				stack->push<int>(result);
			}
			delete[] output;
			return 1;
		}
		return 0;
	}

	int MPI::shiftL(State & state, mbedtls_mpi * mpi){
		Stack * stack = state.stack;
		if (stack->is<LUA_TNUMBER>(1)){
			size_t count = stack->to<int>(1);
			stack->push<int>(mbedtls_mpi_shift_l(mpi, count));
			return 1;
		}
		return 0;
	}
	int MPI::shiftR(State & state, mbedtls_mpi * mpi){
		Stack * stack = state.stack;
		if (stack->is<LUA_TNUMBER>(1)){
			size_t count = stack->to<int>(1);
			stack->push<int>(mbedtls_mpi_shift_r(mpi, count));
			return 1;
		}
		return 0;
	}
	int MPI::cmpAbs(State & state, mbedtls_mpi * mpi){
		Stack * stack = state.stack;
		MPI * interfaceMPI = OBJECT_IFACE(MPI);
		mbedtls_mpi * Y = interfaceMPI->get(1);
		if (Y){
			stack->push<int>(mbedtls_mpi_cmp_abs(mpi, Y));
			return 1;
		}
		return 0;
	}
	int MPI::cmpMPI(State & state, mbedtls_mpi * mpi){
		Stack * stack = state.stack;
		MPI * interfaceMPI = OBJECT_IFACE(MPI);
		mbedtls_mpi * Y = interfaceMPI->get(1);
		if (Y){
			stack->push<int>(mbedtls_mpi_cmp_mpi(mpi, Y));
			return 1;
		}
		return 0;
	}
	int MPI::cmpInt(State & state, mbedtls_mpi * mpi){
		Stack * stack = state.stack;
		if (stack->is<LUA_TNUMBER>(1)){
			mbedtls_mpi_sint Y = static_cast<mbedtls_mpi_sint>(stack->to<int>(1));
			stack->push<int>(mbedtls_mpi_cmp_int(mpi, Y));
			return 1;
		}
		return 0;
	}
	int MPI::addAbs(State & state, mbedtls_mpi * mpi){
		Stack * stack = state.stack;
		MPI * interfaceMPI = OBJECT_IFACE(MPI);
		mbedtls_mpi * X = interfaceMPI->get(1);
		mbedtls_mpi * Y = interfaceMPI->get(2);
		if (X && Y){
			stack->push<int>(mbedtls_mpi_add_abs(mpi, X, Y));
			return 1;
		}
		return 0;
	}
	int MPI::subAbs(State & state, mbedtls_mpi * mpi){
		Stack * stack = state.stack;
		MPI * interfaceMPI = OBJECT_IFACE(MPI);
		mbedtls_mpi * X = interfaceMPI->get(1);
		mbedtls_mpi * Y = interfaceMPI->get(2);
		if (X && Y){
			stack->push<int>(mbedtls_mpi_sub_abs(mpi, X, Y));
			return 1;
		}
		return 0;
	}
	int MPI::addMPI(State & state, mbedtls_mpi * mpi){
		Stack * stack = state.stack;
		MPI * interfaceMPI = OBJECT_IFACE(MPI);
		mbedtls_mpi * X = interfaceMPI->get(1);
		mbedtls_mpi * Y = interfaceMPI->get(2);
		if (X && Y){
			stack->push<int>(mbedtls_mpi_add_mpi(mpi, X, Y));
			return 1;
		}
		return 0;
	}
	int MPI::subMPI(State & state, mbedtls_mpi * mpi){
		Stack * stack = state.stack;
		MPI * interfaceMPI = OBJECT_IFACE(MPI);
		mbedtls_mpi * X = interfaceMPI->get(1);
		mbedtls_mpi * Y = interfaceMPI->get(2);
		if (X && Y){
			stack->push<int>(mbedtls_mpi_sub_mpi(mpi, X, Y));
			return 1;
		}
		return 0;
	}
	int MPI::addInt(State & state, mbedtls_mpi * mpi){
		Stack * stack = state.stack;
		MPI * interfaceMPI = OBJECT_IFACE(MPI);
		mbedtls_mpi * X = interfaceMPI->get(1);
		if (X && stack->is<LUA_TNUMBER>(2)){
			mbedtls_mpi_sint Y = static_cast<mbedtls_mpi_sint>(stack->to<int>(1));
			stack->push<int>(mbedtls_mpi_add_int(mpi, X, Y));
			return 1;
		}
		return 0;
	}
	int MPI::subInt(State & state, mbedtls_mpi * mpi){
		Stack * stack = state.stack;
		MPI * interfaceMPI = OBJECT_IFACE(MPI);
		mbedtls_mpi * X = interfaceMPI->get(1);
		if (X && stack->is<LUA_TNUMBER>(2)){
			mbedtls_mpi_sint Y = static_cast<mbedtls_mpi_sint>(stack->to<int>(1));
			stack->push<int>(mbedtls_mpi_sub_int(mpi, X, Y));
			return 1;
		}
		return 0;
	}
	int MPI::mulMPI(State & state, mbedtls_mpi * mpi){
		Stack * stack = state.stack;
		MPI * interfaceMPI = OBJECT_IFACE(MPI);
		mbedtls_mpi * X = interfaceMPI->get(1);
		mbedtls_mpi * Y = interfaceMPI->get(2);
		if (X && Y){
			stack->push<int>(mbedtls_mpi_mul_mpi(mpi, X, Y));
			return 1;
		}
		return 0;
	}
	int MPI::mulInt(State & state, mbedtls_mpi * mpi){
		Stack * stack = state.stack;
		MPI * interfaceMPI = OBJECT_IFACE(MPI);
		mbedtls_mpi * X = interfaceMPI->get(1);
		if (X && stack->is<LUA_TNUMBER>(2)){
			mbedtls_mpi_sint Y = static_cast<mbedtls_mpi_sint>(stack->to<int>(1));
			stack->push<int>(mbedtls_mpi_mul_int(mpi, X, Y));
			return 1;
		}
		return 0;
	}
	int MPI::divMPI(State & state, mbedtls_mpi * mpi){
		Stack * stack = state.stack;
		MPI * interfaceMPI = OBJECT_IFACE(MPI);
		mbedtls_mpi * Y = interfaceMPI->get(2);
		if (Y){
			mbedtls_mpi * Q = new mbedtls_mpi;
			mbedtls_mpi * R = new mbedtls_mpi;
			mbedtls_mpi_init(Q);
			mbedtls_mpi_init(R);
			int result = mbedtls_mpi_div_mpi(Q, R, mpi, Y);
			if (result == 0){
				interfaceMPI->push(Q, true);
				interfaceMPI->push(R, true);
				return 2;
			}
			else{
				stack->push<int>(result);
				return 1;
			}
		}
		return 0;
	}
	int MPI::divInt(State & state, mbedtls_mpi * mpi){
		Stack * stack = state.stack;
		MPI * interfaceMPI = OBJECT_IFACE(MPI);
		if (stack->is<LUA_TNUMBER>(1)){
			mbedtls_mpi * Q = new mbedtls_mpi;
			mbedtls_mpi * R = new mbedtls_mpi;
			mbedtls_mpi_init(Q);
			mbedtls_mpi_init(R);
			mbedtls_mpi_sint Y = static_cast<mbedtls_mpi_sint>(stack->to<int>(1));
			int result = mbedtls_mpi_div_int(Q, R, mpi, Y);
			if (result == 0){
				interfaceMPI->push(Q, true);
				interfaceMPI->push(R, true);
				return 2;
			}
			else{
				stack->push<int>(result);
				return 1;
			}
		}
		return 0;
	}
	int MPI::modMPI(State & state, mbedtls_mpi * mpi){
		Stack * stack = state.stack;
		MPI * interfaceMPI = OBJECT_IFACE(MPI);
		mbedtls_mpi * X = interfaceMPI->get(1);
		mbedtls_mpi * Y = interfaceMPI->get(2);
		if (X && Y){
			stack->push<int>(mbedtls_mpi_mod_mpi(mpi, X, Y));
			return 1;
		}
		return 0;
	}
	int MPI::modInt(State & state, mbedtls_mpi * mpi){
		Stack * stack = state.stack;
		MPI * interfaceMPI = OBJECT_IFACE(MPI);
		mbedtls_mpi * X = interfaceMPI->get(1);
		if (X && stack->is<LUA_TNUMBER>(2)){
			mbedtls_mpi_sint Y = static_cast<mbedtls_mpi_sint>(stack->to<int>(1));
			mbedtls_mpi_uint r;
			int result = mbedtls_mpi_mod_int(&r, mpi, Y);
			if (result == 0){
				stack->push<LUA_NUMBER>(r);
			}
			else{
				stack->push<int>(result);
			}
			return 1;
		}
		return 0;
	}
	int MPI::expMod(State & state, mbedtls_mpi * mpi){
		Stack * stack = state.stack;
		MPI * interfaceMPI = OBJECT_IFACE(MPI);
		mbedtls_mpi * A = interfaceMPI->get(1);
		mbedtls_mpi * E = interfaceMPI->get(2);
		mbedtls_mpi * N = interfaceMPI->get(3);
		mbedtls_mpi * RR = interfaceMPI->get(4);
		if (A && E && N && RR){
			stack->push<int>(mbedtls_mpi_exp_mod(mpi, A, E, N, RR));
			return 1;
		}
		return 0;
	}
	int MPI::fillRandom(State & state, mbedtls_mpi * mpi){
		Stack * stack = state.stack;
		CTRDRBGContext * interfaceCTRDRBGContext = OBJECT_IFACE(CTRDRBGContext);
		mbedtls_ctr_drbg_context * drbg = interfaceCTRDRBGContext->get(2);
		if (drbg && stack->is<LUA_TNUMBER>(1)){
			size_t size = stack->to<int>(1);
			stack->push<int>(mbedtls_mpi_fill_random(mpi, size, mbedtls_ctr_drbg_random, drbg));
			return 1;
		}
		return 0;
	}
	int MPI::GCD(State & state, mbedtls_mpi * mpi){
		Stack * stack = state.stack;
		MPI * interfaceMPI = OBJECT_IFACE(MPI);
		mbedtls_mpi * X = interfaceMPI->get(1);
		mbedtls_mpi * Y = interfaceMPI->get(2);
		if (X && Y){
			stack->push<int>(mbedtls_mpi_gcd(mpi, X, Y));
			return 1;
		}
		return 0;
	}
	int MPI::invMod(State & state, mbedtls_mpi * mpi){
		Stack * stack = state.stack;
		MPI * interfaceMPI = OBJECT_IFACE(MPI);
		mbedtls_mpi * X = interfaceMPI->get(1);
		mbedtls_mpi * Y = interfaceMPI->get(2);
		if (X && Y){
			stack->push<int>(mbedtls_mpi_inv_mod(mpi, X, Y));
			return 1;
		}
		return 0;
	}
	int MPI::isPrime(State & state, mbedtls_mpi * mpi){
		Stack * stack = state.stack;
		CTRDRBGContext * interfaceCTRDRBGContext = OBJECT_IFACE(CTRDRBGContext);
		mbedtls_ctr_drbg_context * drbg = interfaceCTRDRBGContext->get(1);
		if (drbg){
			stack->push<int>(mbedtls_mpi_is_prime(mpi, mbedtls_ctr_drbg_random, drbg));
			return 1;
		}
		return 0;
	}
	int MPI::genPrime(State & state, mbedtls_mpi * mpi){
		Stack * stack = state.stack;
		CTRDRBGContext * interfaceCTRDRBGContext = OBJECT_IFACE(CTRDRBGContext);
		mbedtls_ctr_drbg_context * drbg = interfaceCTRDRBGContext->get(3);
		if (drbg && stack->is<LUA_TNUMBER>(1) && stack->is<LUA_TNUMBER>(2)){
			size_t nbits = stack->to<int>(1);
			int dhFlag = stack->to<int>(2);
			stack->push<int>(mbedtls_mpi_gen_prime(mpi, nbits, dhFlag, mbedtls_ctr_drbg_random, drbg));
			return 1;
		}
		return 0;
	}

	int MPISelfTest(State & state){
		Stack * stack = state.stack;
		stack->push<int>(mbedtls_mpi_self_test(stack->to<int>(1)));
		return 1;
	}

	void initMPI(State * state, Module & module){
		INIT_OBJECT(MPI);
		module["MPISelfTest"] = MPISelfTest;
	}
};
