cmake_minimum_required(VERSION 3.28)
project(mcas)

set(CMAKE_CXX_STANDARD 17)

add_executable(mcas main.cpp
        src/TcpConnection.cpp
        src/TcpConnection.h
        src/protocol/handshake.h
        src/protocol/handshake.cpp
        src/leb128.h
        src/leb128.cpp
        src/protocol/protocol.cpp
        src/protocol/protocol.h
        src/protocol/login.cpp
        src/protocol/login.h
        src/protocol/common.h
        src/encryption/RSAEncryption.cpp
        src/encryption/RSAEncryption.h
        src/encryption/AESEncryption.cpp
        src/encryption/AESEncryption.h
        src/hash.h
        src/session.cpp
        src/session.h
        src/protocol/login_play.cpp
        src/protocol/login_play.h
        src/protocol/types.h
        src/externalAuth.cpp
        src/externalAuth.h)


find_package(OpenSSL REQUIRED)
#message(STATUS "OpenSSL version: ${OpenSSL_VERSION}")
target_link_libraries(mcas OpenSSL::SSL)

find_package(CURL REQUIRED)
#message(STATUS "CURL version: ${CURL_VERSION}")
include_directories(${CURL_INCLUDE_DIR})
target_link_libraries(mcas ${CURL_LIBRARIES})

find_package(cJSON REQUIRED)
message(STATUS "cJSON version: ${cJSON_VERSION}")
include_directories(${CJSON_INCLUDE_DIRS})
target_link_libraries(mcas ${CJSON_LIBRARIES})
