cmake_minimum_required(VERSION 3.22.1)
project("shell")

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Wextra")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -Wextra -fexceptions -frtti")

# O-LLVM obfuscation (enable with -DENABLE_OBFUSCATION=ON)
if(ENABLE_OBFUSCATION)
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -mllvm -fla -mllvm -sub -mllvm -bcf")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -mllvm -fla -mllvm -sub -mllvm -bcf")
endif()

# Source files - matching dpt-shell structure exactly
set(SHELL_SOURCES
    dpt.cpp
    dpt_crypto.cpp
    dpt_hook.cpp
    dpt_jni.cpp
    dpt_risk.cpp
    dpt_util.cpp
    common/dpt_string.cpp
    dex/CodeItem.cpp
    dex/MultiDexCode.cpp
    dex/dex_file.cpp
    rc4/rc4.c
    reflect/android_app_ActivityThread.cpp
    reflect/android_app_Application.cpp
    reflect/android_app_ContextImpl.cpp
    reflect/android_app_LoadedApk.cpp
    reflect/android_content_pm_ApplicationInfo.cpp
    reflect/dalvik_system_BaseDexClassLoader.cpp
    reflect/dalvik_system_DexPathList.cpp
    reflect/java_io_File.cpp
    reflect/java_lang_Class.cpp
    reflect/java_util_ArrayList.cpp
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
