cmake_minimum_required(VERSION 3.10)

project(IronVault C)

# Set C standard
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

# Compiler flags for security and optimization
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Wextra -fPIC")
set(CMAKE_C_FLAGS_RELEASE "${CMAKE_C_FLAGS_RELEASE} -O3 -DNDEBUG")

# Core library source files
set(CORE_SOURCES
    core/src/security_core.c
    core/src/auth_state_machine.c
    core/src/key_manager.c
    core/crypto/crypto.c
)

# Core library headers
set(CORE_HEADERS
    core/include/security_core.h
    core/include/auth_state_machine.h
    core/include/key_manager.h
    core/include/crypto.h
)

# Create static library for core
add_library(ironvault_core STATIC ${CORE_SOURCES})
target_include_directories(ironvault_core PUBLIC 
    ${CMAKE_CURRENT_SOURCE_DIR}/core/include
)

# Create shared library for JNI (Android)
if(ANDROID)
    add_library(ironvault_jni SHARED
        ${CORE_SOURCES}
        android/jni/ironvault_jni.c
    )
    target_include_directories(ironvault_jni PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/core/include
    )
    target_link_libraries(ironvault_jni log)
endif()

# Installation
install(TARGETS ironvault_core
    ARCHIVE DESTINATION lib
)

install(FILES ${CORE_HEADERS}
    DESTINATION include/ironvault
)

# Print configuration
message(STATUS "IronVault SDK Configuration:")
message(STATUS "  Build type: ${CMAKE_BUILD_TYPE}")
message(STATUS "  C Compiler: ${CMAKE_C_COMPILER}")
message(STATUS "  C Flags: ${CMAKE_C_FLAGS}")
