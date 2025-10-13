cmake_minimum_required(VERSION 3.10)
project(rule2bin VERSION 1.0.0 LANGUAGES CXX)

# Set C++ standard
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Project structure
set(INCLUDE_DIR include)
set(SOURCE_DIR src)
set(TEST_DIR tests)

# Find zlib for CRC32
find_package(ZLIB REQUIRED)

# Create library
add_library(rule2bin
    ${SOURCE_DIR}/structures.cpp
    ${SOURCE_DIR}/rule_parser.cpp
    ${SOURCE_DIR}/binary_serializer.cpp
    ${SOURCE_DIR}/binary_deserializer.cpp
)

# Link zlib
target_link_libraries(rule2bin ZLIB::ZLIB)

# Include directories
target_include_directories(rule2bin PUBLIC ${INCLUDE_DIR})

# Main executable
add_executable(rule2bin_cli ${SOURCE_DIR}/main.cpp)
target_link_libraries(rule2bin_cli rule2bin)

# Installation
install(TARGETS rule2bin_cli DESTINATION bin)
install(TARGETS rule2bin DESTINATION lib)
install(DIRECTORY ${INCLUDE_DIR}/ DESTINATION include)

# Testing (if GoogleTest is available)
if(EXISTS ${CMAKE_SOURCE_DIR}/tests)
    enable_testing()
    add_subdirectory(tests)
endif()

# Compiler warnings
if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
    target_compile_options(rule2bin PRIVATE -Wall -Wextra -Wpedantic)
endif()