cmake_minimum_required(VERSION 3.10)
project(ids CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# 设置输出目录
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR})
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR})

# 查找所需的包
find_package(Threads REQUIRED)

# 包含目录
include_directories(include)

# 源文件
set(SOURCES
    src/ids.cpp
    src/capture/af_packet.cpp
    src/capture/factory.cpp
    src/utils/utils.cpp
    src/utils/packet_formatter.cpp
    src/parsing/tcp.cpp
    src/parsing/info_extractor.cpp
    src/rule/parser.cpp
    src/rule/matcher.cpp
)

# 核心库
add_library(ids_core STATIC ${SOURCES})

# 链接库
target_link_libraries(ids_core PRIVATE Threads::Threads)

# 主可执行文件
add_executable(ids src/main.cpp)
target_link_libraries(ids PRIVATE ids_core)