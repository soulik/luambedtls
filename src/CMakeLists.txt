set(luambedtls_src
	main.cpp
	constants.cpp
	utils.cpp
)

set(luambedtls_h
	common.hpp
	utils.hpp
)

set(luambedtls_objects_src
	objects/ASN1buf.cpp
	objects/ASN1named.cpp

	objects/AESContext.cpp
	objects/ARC4Context.cpp
	objects/BlowfishContext.cpp
	objects/CamelliaContext.cpp
	objects/DESContext.cpp
	objects/DES3Context.cpp
	objects/GCMContext.cpp
	objects/XTEAContext.cpp

	objects/MDContext.cpp

	objects/DHMContext.cpp
	objects/RSAContext.cpp

	objects/CTRDRBGContext.cpp
	objects/DHMContext.cpp
	objects/EntropyContext.cpp
	objects/PKContext.cpp
	objects/SSLConfig.cpp
	objects/SSLContext.cpp
	objects/SSLSession.cpp
	objects/x509crt.cpp
	objects/x509crl.cpp
	objects/x509crtProfile.cpp
	objects/x509csr.cpp
	objects/TimingDelayContext.cpp
)

set(luambedtls_objects_hdr
	objects/ASN1buf.hpp
	objects/ASN1named.hpp

	objects/AESContext.hpp
	objects/ARC4Context.hpp
	objects/BlowfishContext.hpp
	objects/CamelliaContext.hpp
	objects/DESContext.hpp
	objects/DES3Context.hpp
	objects/GCMContext.hpp
	objects/XTEAContext.hpp

	objects/MDContext.hpp

	objects/DHMContext.hpp
	objects/RSAContext.hpp

	objects/CTRDRBGContext.hpp
	objects/DHMContext.hpp
	objects/EntropyContext.hpp
	objects/PKContext.hpp
	objects/SSLConfig.hpp
	objects/SSLContext.hpp
	objects/SSLSession.hpp
	objects/x509crt.hpp
	objects/x509crl.hpp
	objects/x509crtProfile.hpp
	objects/x509csr.hpp
	objects/TimingDelayContext.hpp
)

set(luambedtls_sources
	${luambedtls_src} ${luambedtls_h}
	${luambedtls_objects_src} ${luambedtls_objects_hdr}
)

include_directories(./)

source_group("Header files" FILES ${luambedtls_h})
source_group(objects FILES ${luambedtls_objects_src} ${luambedtls_objects_hdr})


set(luambedtls_version_script luambedtls.version)

IF(UNIX)
    IF(CMAKE_COMPILER_IS_GNUCC)
         SET(CMAKE_SHARED_LINKER_FLAGS  "${CMAKE_SHARED_LINKER_FLAGS} ${CMAKE_CXX_COMPILE_OPTIONS_VISIBILITY}hidden -Wl,--version-script=${CMAKE_CURRENT_SOURCE_DIR}/${luambedtls_version_script}")
    ENDIF(CMAKE_COMPILER_IS_GNUCC)

    SET(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wmissing-declarations")
ENDIF(UNIX)

add_library(luambedtls SHARED
	${luambedtls_sources}
)

set_property(TARGET luambedtls PROPERTY CXX_STANDARD 11)
set_property(TARGET luambedtls PROPERTY CXX_STANDARD_REQUIRED ON)

set_target_properties(luambedtls
    PROPERTIES
    ARCHIVE_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/lib"
    LIBRARY_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/lib"
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin"
)

set(luambedtls_LIBRARIES
	mbedtls
	mbedcrypto
	mbedx509
)


configure_file(mbedtls.lua ${CMAKE_BINARY_DIR}/lib/mbedtls.lua COPYONLY)

target_link_libraries (luambedtls
	${luambedtls_LIBRARIES}
	${LUA_LIBRARY}
)

