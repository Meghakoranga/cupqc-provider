cmake_minimum_required(VERSION 3.18)
project(cupqc-provider VERSION 1.0.0 LANGUAGES C)

# Find OpenSSL 3.x (must be installed on system)
find_package(OpenSSL 3.0 REQUIRED COMPONENTS Crypto)

# Build the provider as a MODULE (shared library for dlopen)
add_library(cupqcprov MODULE
    src/cupqcprov.c
    src/kem_mlkem_cupqc.c
    src/keymgmt_mlkem_cupqc.c
    src/cupqc_wrap.c
)

# Include directories
target_include_directories(cupqcprov PRIVATE
    ${OPENSSL_INCLUDE_DIR}
    src
)

# Link against OpenSSL crypto and dl (for dlopen)
# Note: libcupqc.so is dynamically loaded at runtime
target_link_libraries(cupqcprov PRIVATE OpenSSL::Crypto dl)

# Provider modules must not have "lib" prefix
set_target_properties(cupqcprov PROPERTIES
    PREFIX ""
    OUTPUT_NAME "cupqcprov"
    SUFFIX ".so"
)

# Installation directory (can override with -DOPENSSL_MODULES_DIR=...)
if(NOT DEFINED OPENSSL_MODULES_DIR)
    set(OPENSSL_MODULES_DIR "/usr/local/lib64/ossl-modules")
endif()

install(TARGETS cupqcprov LIBRARY DESTINATION ${OPENSSL_MODULES_DIR})
