local bit = require 'bit'
local tls = require 'luambedtls'
require 'utils'
local dump = (require 'utils/dump').dump

local function getType(o)
	local mt = getmetatable(o)
	if type(mt)=='table' then
		return mt.__typename
	else
		return type(o)
	end
end

local function TLS_assert(...)
	local errn = select(1, ...)
	if type(errn)=='number' and errn ~= 0 then
		error(tls.strError(errn))
	else
		return ...
	end
end

local function create(options)

    local entropy = tls.EntropyContext()
    local CTR_DRBG = tls.CTRDRBGContext()
    CTR_DRBG.seed(entropy, "gen_cert")

    local crt = tls.x509writeCert()
    crt.MDAlg = tls.MD_SHA256

    local issuerCrt = tls.x509crt()
    local crtRequest = tls.x509csr()
    local issuerKey, subjectKey = tls.PKContext(), tls.PKContext()
    local serial = tls.MPI()

    TLS_assert(serial.readString(10, options.serial))

    if not options.selfsign then
    	if type(options.issuerCrt)=='string' then
   			TLS_assert(issuerCrt.parseFile(options.issuerCrt))
   			options.issuerName = issuerCrt.subject.s
   		end

    	if type(options.crtRequest)=='string' then
    		TLS_assert(crtRequest.parseFile(options.crtRequest))
    		options.subjectName = crtRequest.subject.s
    		subjectKey = crtRequest.pk 
    	else
    		TLS_assert(subjectKey.parseKeyFile(options.subjectKey, options.subjectPwd))
    	end
    end

    TLS_assert(issuerKey.parseKeyFile(options.issuerKey, options.issuerPwd))

    if options.issuerCrt then
    	local pkCrt = issuerCrt.pk
    	local pkKey = issuerKey
    	assert(pkCrt and pkKey)

    	if pkCrt.canDo(tls.PK_RSA) then
    		local rC = pkCrt.rsa
    		local rK = pkKey.rsa
    		assert(rC and rK)

    		assert((rC.N.cmpMPI(rK.N) == 0) and (rC.E.cmpMPI(rK.E) == 0), 'Issuer key does not match issuer certificate')
    	end
    end

    if options.selfSign then
    	options.subjectName = options.issuerName
    	subjectKey = issuerKey
    end

    crt.subjectKey = subjectKey
    crt.issuerKey = issuerKey

    crt.subjectName = options.subjectName
    crt.issuerName = options.issuerName

    crt.serial = serial

    TLS_assert(crt.validity(options.notBefore, options.notAfter))
    TLS_assert(crt.basicContraints(options.isCA, options.maxPathLen))
    TLS_assert(crt.subjectKeyIdentifier())
    TLS_assert(crt.authorityKeyIdentifier())

    if options.keyUsage then
    	TLS_assert(crt.keyUsage(options.keyUsage))
    end

    if options.NSCertType then
    	TLS_assert(crt.NSCertType(options.NSCertType))
    end

    local crtStr = TLS_assert(crt.writePEM(2048, CTR_DRBG))
    crtStr = crtStr:sub(1,crtStr:find("\0"))

    assert(io.open(options.output,'w')):write(crtStr):close()
end

return {
	create = create,
}

