namespace luambedtls {
	void initMPI(State * state, Module & module);
	void initASN1buf(State * state, Module & module);
	void initASN1named(State * state, Module & module);

	void initAESContext(State * state, Module & module);
	void initARC4Context(State * state, Module & module);
	void initBlowfishContext(State * state, Module & module);
	void initCamelliaContext(State * state, Module & module);
	void initDESContext(State * state, Module & module);
	void initDES3Context(State * state, Module & module);
	void initGCMContext(State * state, Module & module);
	void initXTEAContext(State * state, Module & module);

	void initDHMContext(State * state, Module & module);
	void initRSAContext(State * state, Module & module);

	void initMDContext(State * state, Module & module);
	void initMDinfo(State * state, Module & module);

	void initPKContext(State * state, Module & module);
	void initPKinfo(State * state, Module & module);

	void initECPCurveInfo(State * state, Module & module);
	void initECPPoint(State * state, Module & module);
	void initECPGroup(State * state, Module & module);
	void initECPKeyPair(State * state, Module & module);
	void initECDHContext(State * state, Module & module);
	void initECSDAContext(State * state, Module & module);

	void initEntropyContext(State * state, Module & module);
	void initSSLConfig(State * state, Module & module);
	void initSSLContext(State * state, Module & module);
	void initSSLSession(State * state, Module & module);
	void initx509crt(State * state, Module & module);
	void initx509crl(State * state, Module & module);
	void initx509crlEntry(State * state, Module & module);
	void initx509crtProfile(State * state, Module & module);
	void initx509csr(State * state, Module & module);
	void initx509writeCert(State * state, Module & module);
	void initx509writeCSR(State * state, Module & module);
	void initCTRDRBGContext(State * state, Module & module);
	void initTimingDelayContext(State * state, Module & module);

	void initCipherContext(State * state, Module & module);
	void initCipherInfo(State * state, Module & module);

	void initConstants(State * state, Module & module);

	void initUtils(State * state, Module & module);
};
