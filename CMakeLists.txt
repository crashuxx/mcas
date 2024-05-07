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
        src/protocol/types.h)


find_package(OpenSSL REQUIRED)
target_link_libraries(mcas OpenSSL::SSL)
