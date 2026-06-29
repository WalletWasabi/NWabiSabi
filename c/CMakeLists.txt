cmake_minimum_required(VERSION 3.14)
project(wabisabi C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

include(FetchContent)

# Fetch secp256k1
FetchContent_Declare(
    secp256k1
    GIT_REPOSITORY https://github.com/bitcoin-core/secp256k1.git
    GIT_TAG v0.7.1
)
set(SECP256K1_BUILD_TESTS OFF CACHE BOOL "" FORCE)
set(SECP256K1_BUILD_EXHAUSTIVE_TESTS OFF CACHE BOOL "" FORCE)
set(SECP256K1_BUILD_BENCHMARK OFF CACHE BOOL "" FORCE)
set(SECP256K1_BUILD_EXAMPLES OFF CACHE BOOL "" FORCE)
set(SECP256K1_ENABLE_MODULE_RECOVERY OFF CACHE BOOL "" FORCE)
FetchContent_MakeAvailable(secp256k1)

# WabiSabi shared library (core protocol + serialization layer for P/Invoke)
add_library(wabisabi SHARED
    src/sha256.c
    src/strobe.c
    src/field.c
    src/wabisabi_types.c
    src/generators.c
    src/mac.c
    src/transcript.c
    src/proof.c
    src/credential.c
    src/issuer.c
    src/client.c
    src/ffi.c
)

target_include_directories(wabisabi
    PUBLIC  include
    PRIVATE src
    PRIVATE ${secp256k1_SOURCE_DIR}/include
)

target_link_libraries(wabisabi PRIVATE secp256k1)

target_compile_options(wabisabi PRIVATE
    -Wall -Wextra -Wpedantic
    $<$<CONFIG:Release>:-O2>
    $<$<CONFIG:Debug>:-g -O0 -U_FORTIFY_SOURCE>
)

# Test executable
add_executable(wabisabi_test tests/test_main.c tests/test_compat.c)
target_include_directories(wabisabi_test PRIVATE include src
    ${secp256k1_SOURCE_DIR}/include)
target_link_libraries(wabisabi_test PRIVATE wabisabi secp256k1)
