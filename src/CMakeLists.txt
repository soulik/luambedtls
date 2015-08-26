set(luambedtls_src
	main.cpp
)

set(luambedtls_h
	common.hpp
)

set(luambedtls_sources
	${luambedtls_src} ${luambedtls_h}
)

include_directories(./)

source_group("Header files" FILES ${luambedtls_h})

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

configure_file(mbedtls.lua ${CMAKE_BINARY_DIR}/lib/mbedtls.lua COPYONLY)

target_link_libraries (luambedtls
	${LUA_LIBRARY}
)

