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
# Force secp256k1 to build as a static archive so it is embedded directly into
# libwabisabi (no runtime dependency on libsecp256k1.so.N). secp256k1's
# add_library() follows BUILD_SHARED_LIBS, which some build environments
# (e.g. the nixpkgs cmake hook) default to ON — that would make libwabisabi
# dynamically NEED libsecp256k1.so.2 and fail to load on consumers that don't
# ship it. Override here and restore afterwards; our own `wabisabi` target is
# declared SHARED explicitly, so it is unaffected.
set(_wabisabi_saved_build_shared "${BUILD_SHARED_LIBS}")
set(BUILD_SHARED_LIBS OFF)
FetchContent_MakeAvailable(secp256k1)
set(BUILD_SHARED_LIBS "${_wabisabi_saved_build_shared}")

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

# Keep symbols from the statically-linked secp256k1 archive out of libwabisabi's
# dynamic symbol table. Otherwise the ~70 secp256k1_* symbols are re-exported
# with default visibility and can collide (via ELF symbol interposition) with a
# host process that loads its own libsecp256k1 — common in Bitcoin tooling.
# GNU ld / lld only; macOS ld64 and Windows DLLs don't auto-export archive
# symbols, so the flag is neither available nor needed there.
if(NOT APPLE AND NOT WIN32)
    target_link_options(wabisabi PRIVATE -Wl,--exclude-libs,ALL)
endif()

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
