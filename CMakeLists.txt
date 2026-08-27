cmake_minimum_required(VERSION 3.16)
project(chat_protobuf_tls LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# ============================================================
# 1. 设置源文件目录
# ============================================================
# 如果 CMakeLists.txt 在项目根目录，源文件在 src 子目录
set(SRC_DIR ${CMAKE_CURRENT_SOURCE_DIR}/src)

# 如果 CMakeLists.txt 在 src 目录，取消下面的注释，注释掉上面的
# set(SRC_DIR ${CMAKE_CURRENT_SOURCE_DIR})

# ============================================================
# 2. 生成 protobuf 文件
# ============================================================
# 查找 protobuf
find_package(Protobuf REQUIRED)

# 生成 chat.pb.cc 和 chat.pb.h
PROTOBUF_GENERATE_CPP(PROTO_SRCS PROTO_HDRS ${SRC_DIR}/chat.proto)

# ============================================================
# 3. 查找其他依赖
# ============================================================
find_package(OpenSSL REQUIRED)
find_package(CURL REQUIRED)
find_package(Threads REQUIRED)

find_library(HIREDIS_LIB hiredis REQUIRED)
find_library(LEVELDB_LIB leveldb REQUIRED)
find_library(MYSQLCLIENT_LIB mysqlclient REQUIRED)

# ============================================================
# 4. 源文件列表
# ============================================================
set(COMMON_SOURCES
    ${SRC_DIR}/chat_utils.cpp
    ${PROTO_SRCS}           # 使用生成的 protobuf 源文件
)

set(SERVER_SOURCES
    ${SRC_DIR}/server.cpp
    ${SRC_DIR}/file_transfer.cpp
    ${SRC_DIR}/send_email.cpp
    ${COMMON_SOURCES}
)

set(CLIENT_SOURCES
    ${SRC_DIR}/client.cpp
    ${COMMON_SOURCES}
)

# ============================================================
# 5. 包含目录
# ============================================================
include_directories(${SRC_DIR})
include_directories(${CMAKE_CURRENT_BINARY_DIR})  # 添加：protobuf 生成文件的目录
include_directories(${PROTOBUF_INCLUDE_DIRS})

# ============================================================
# 6. 服务器可执行文件
# ============================================================
add_executable(chat_server ${SERVER_SOURCES})
target_link_libraries(chat_server
    OpenSSL::SSL 
    OpenSSL::Crypto 
    CURL::libcurl
    ${HIREDIS_LIB} 
    ${LEVELDB_LIB} 
    ${MYSQLCLIENT_LIB}
    ${PROTOBUF_LIBRARIES}
    Threads::Threads
)

# ============================================================
# 7. 客户端可执行文件
# ============================================================
add_executable(chat_client ${CLIENT_SOURCES})
target_link_libraries(chat_client
    OpenSSL::SSL 
    OpenSSL::Crypto
    ${PROTOBUF_LIBRARIES}
    Threads::Threads
)

# ============================================================
# 8. 编译选项
# ============================================================
target_compile_options(chat_server PRIVATE -Wall -Wextra)
target_compile_options(chat_client PRIVATE -Wall -Wextra)

# ============================================================
# 9. 导出编译命令（帮助 IDE 解析）
# ============================================================
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)