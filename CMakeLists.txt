cmake_minimum_required (VERSION 3.1.0)
project (luambedtls)

# Include Lua 5.1

include(FindLua51)
include_directories(SYSTEM
	${LUA_INCLUDE_DIR}
	${LUA_INCLUDE_DIR}/lua5.1
)

# Include zlib

add_subdirectory(dependencies/zlib-1.2.8)
include_directories(dependencies/zlib-1.2.8)

set_target_properties(zlib
    PROPERTIES
    ARCHIVE_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/${CMAKE_SYSTEM_PROCESSOR}/lib"
    LIBRARY_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/${CMAKE_SYSTEM_PROCESSOR}/lib"
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/${CMAKE_SYSTEM_PROCESSOR}/bin"
)

set_target_properties(zlibstatic
    PROPERTIES
    ARCHIVE_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/${CMAKE_SYSTEM_PROCESSOR}/lib"
    LIBRARY_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/${CMAKE_SYSTEM_PROCESSOR}/lib"
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/${CMAKE_SYSTEM_PROCESSOR}/bin"
)

# Include mbedtls 2.0.0

set(ZLIB_LIBRARY $<TARGET_LINKER_FILE:zlib>)
set(ZLIB_INCLUDE_DIR ${luambedtls_SOURCE_DIR}/dependencies/zlib-1.2.8)

# add_subdirectory(dependencies/mbedtls-2.0.0)
# include_directories(dependencies/mbedtls-2.0.0/include)
add_subdirectory(dependencies/mbedtls)
include_directories(dependencies/mbedtls/include)

if (USE_STATIC_MBEDTLS_LIBRARY AND USE_SHARED_MBEDTLS_LIBRARY)
	set(mbedtls_static_library "mbedtls_static")
	set(mbedcrypto_static_library "mbedcrypto_static")
	set(mbedx509_static_library "mbedx509_static")
else()
	set(mbedtls_static_library "mbedtls")
	set(mbedcrypto_static_library "mbedcrypto")
	set(mbedx509_static_library "mbedx509")
endif()

set_target_properties(${mbedtls_static_library}
    PROPERTIES
    ARCHIVE_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/${CMAKE_SYSTEM_PROCESSOR}/lib"
    LIBRARY_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/${CMAKE_SYSTEM_PROCESSOR}/lib"
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/${CMAKE_SYSTEM_PROCESSOR}/bin"
    DEFINE_SYMBOL "MBEDTLS_EXPORTS"
)

set_target_properties(${mbedcrypto_static_library}
    PROPERTIES
    ARCHIVE_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/${CMAKE_SYSTEM_PROCESSOR}/lib"
    LIBRARY_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/${CMAKE_SYSTEM_PROCESSOR}/lib"
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/${CMAKE_SYSTEM_PROCESSOR}/bin"
    DEFINE_SYMBOL "MBEDTLS_EXPORTS"
)

set_target_properties(${mbedx509_static_library}
    PROPERTIES
    ARCHIVE_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/${CMAKE_SYSTEM_PROCESSOR}/lib"
    LIBRARY_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/${CMAKE_SYSTEM_PROCESSOR}/lib"
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}${CMAKE_SYSTEM_PROCESSOR}//bin"
    DEFINE_SYMBOL "MBEDTLS_EXPORTS"
)

if (UNIX)
	set_target_properties(${mbedtls_static_library}
	    PROPERTIES
	    COMPILE_FLAGS "-fPIC"
	)
	set_target_properties(${mbedcrypto_static_library}
	    PROPERTIES
	    COMPILE_FLAGS "-fPIC"
	)
	set_target_properties(${mbedx509_static_library}
	    PROPERTIES
	    COMPILE_FLAGS "-fPIC"
	)
endif()

# Include lutok2

include_directories(dependencies/lutok2/include)

add_subdirectory(src)

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY build)
set_target_properties(luambedtls PROPERTIES PREFIX "")

