# CMakeLists.txt for FuckProtect shell native library.
#
# This builds libshell.so which handles:
# - AES-256-CBC DEX decryption
# - Anti-debugging checks
# - Signature / integrity verification
# - Method reconstruction (future)

cmake_minimum_required(VERSION 3.22.1)
project("shell")

# ─── Compiler flags ──────────────────────────────────────────────────
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Wextra")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -Wextra -fexceptions -frtti")

# O-LLVM obfuscation flags (enabled via -DENABLE_OBFUSCATION=ON)
if(ENABLE_OBFUSCATION)
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -mllvm -fla -mllvm -sub -mllvm -bcf")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -mllvm -fla -mllvm -sub -mllvm -bcf")
    message(STATUS "O-LLVM obfuscation enabled")
endif()

# ─── AES implementation ──────────────────────────────────────────────
# Using a standalone TinyAES implementation (public domain) to avoid
# OpenSSL dependency. The TinyAES library is small and self-contained.
# Alternatively, add: find_library(log-lib log) and link against libcrypto.

# ─── Source files ────────────────────────────────────────────────────
# shell_native.cpp #include's most .c/.cpp files directly for single
# compilation unit (easier inlining, fewer symbol visibility issues).
set(SHELL_SOURCES
    shell_native.cpp
)

# ─── Build shared library ────────────────────────────────────────────
add_library(shell SHARED ${SHELL_SOURCES})

# ─── Include directories ─────────────────────────────────────────────
target_include_directories(shell PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/crypto
    ${CMAKE_CURRENT_SOURCE_DIR}/antidbg
    ${CMAKE_CURRENT_SOURCE_DIR}/utils
)

# ─── Link libraries ──────────────────────────────────────────────────
find_library(log-lib log)
find_library(android-lib android)

target_link_libraries(shell
    ${log-lib}
    ${android-lib}
)
