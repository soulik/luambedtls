namespace luambedtls {
	int pushOIDAttrShortName(State & state);
	int pushOIDNumericString(State & state);
	int pushOIDExtType(State & state);
	int pushOIDPkAlg(State & state);
	
	void initUtils(State*, Module&);
	int base64Encode(State &);
	int base64Decode(State &);
	int base64SelfTest(State &);
};