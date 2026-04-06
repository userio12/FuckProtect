cmake_minimum_required(VERSION 3.22.1)
project("shell")

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Wextra")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -Wextra -fexceptions -frtti")

# O-LLVM obfuscation (enable with -DENABLE_OBFUSCATION=ON)
if(ENABLE_OBFUSCATION)
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -mllvm -fla -mllvm -sub -mllvm -bcf")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -mllvm -fla -mllvm -sub -mllvm -bcf")
endif()

# Source files - matching dpt-shell structure
set(SHELL_SOURCES
    dpt.cpp
    dpt_risk.cpp
    dpt_util.cpp
    dpt_protect.cpp
    dpt_hook.cpp
    dpt_plt.cpp
    dpt_anti_hook.cpp
    dpt_verify.cpp
    dpt_integrity.cpp
    dpt_crypto.c
    dpt_key.c
    dpt_string.cpp
    rc4/rc4.c
    common/dpt_string.cpp
    reflect/java_lang_System.cpp
)

add_library(shell SHARED ${SHELL_SOURCES})

target_include_directories(shell PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/common
    ${CMAKE_CURRENT_SOURCE_DIR}/dex
    ${CMAKE_CURRENT_SOURCE_DIR}/rc4
    ${CMAKE_CURRENT_SOURCE_DIR}/reflect
)

find_library(log-lib log)
find_library(android-lib android)

target_link_libraries(shell ${log-lib} ${android-lib})
