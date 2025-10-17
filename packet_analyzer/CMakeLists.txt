cmake_minimum_required(VERSION 3.10)
project(ids)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Compiler flags
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -Wextra -Wpedantic -Werror")

# 设置输出目录
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR})
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR})

# 查找所需的包
find_package(Threads REQUIRED)

# 包含目录
include_directories(include)

# Source files
set(SOURCES
    src/main.cpp
    src/ids.cpp
    src/utils/utils.cpp
    src/packetio/af_packet.cpp
    src/packetio/factory.cpp
    src/protocols/ethernet.cpp
    src/protocols/ip.cpp
    src/protocols/tcp.cpp
    src/protocols/info_extractor.cpp
    src/rule/rule.cpp
    src/rule/parser.cpp
    src/rule/matcher.cpp
)

# Create executable
add_executable(${PROJECT_NAME} ${SOURCES})

# Link libraries
target_link_libraries(${PROJECT_NAME} PRIVATE Threads::Threads)