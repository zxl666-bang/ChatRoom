cmake_minimum_required(VERSION 3.10)
project(ChatRoom)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

find_package(OpenSSL REQUIRED)
find_package(CURL REQUIRED)
find_package(Threads REQUIRED)
find_package(PkgConfig REQUIRED)
pkg_check_modules(MYSQL REQUIRED mysqlclient)
set(MYSQL_INCLUDE_DIRS "/usr/include/mysql")
set(MYSQL_LIBRARIES "mysqlclient")

if(NOT MYSQL_INCLUDE_DIRS)
    message(FATAL_ERROR "MYSQL_INCLUDE_DIRS is empty!")
else()
    message(STATUS "MYSQL_INCLUDE_DIRS = ${MYSQL_INCLUDE_DIRS}")
endif()
find_library(HIREDIS_LIB hiredis REQUIRED)
find_path(HIREDIS_INCLUDE hiredis/hiredis.h REQUIRED)
find_library(LEVELDB_LIB leveldb REQUIRED)
find_path(LEVELDB_INCLUDE leveldb/db.h REQUIRED)
include_directories(/usr/include/mysql)
set(SERVER_SOURCES src/server.cpp src/file_transfer.cpp src/send_email.cpp)
set(CLIENT_SOURCES src/client.cpp)
add_executable(chat_server ${SERVER_SOURCES})
target_include_directories(chat_server PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/src
    ${HIREDIS_INCLUDE}
    ${LEVELDB_INCLUDE}
    ${OPENSSL_INCLUDE_DIR}
    ${CURL_INCLUDE_DIR}
  
)
target_link_libraries(chat_server
    ${HIREDIS_LIB}
    ${LEVELDB_LIB}
    ${OPENSSL_LIBRARIES}
    ${CURL_LIBRARIES}
    ${MYSQL_LIBRARIES}
    Threads::Threads
    pthread
)

add_executable(chat_client ${CLIENT_SOURCES})
target_include_directories(chat_client PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/src
    ${OPENSSL_INCLUDE_DIR}
    ${CURL_INCLUDE_DIR}
)
target_link_libraries(chat_client
    ${OPENSSL_LIBRARIES}
    ${CURL_LIBRARIES}
    Threads::Threads
    pthread
)

target_compile_options(chat_server PRIVATE -Wall -Wextra)
target_compile_options(chat_client PRIVATE -Wall -Wextra)