cmake_minimum_required(VERSION 3.5.1)
project(socketwrapper)

set(CMAKE_CXX_STANDARD 11)

set(SOURCES
        main.cpp
        BaseSocket.cpp
        UDPSocket.cpp
        TCPSocket.cpp
        Exceptions/SocketCreationException.cpp
        Exceptions/SocketCloseException.cpp
        Exceptions/SocketBoundException.cpp
        Exceptions/SocketBindException.cpp
        )

add_executable(socketwrapper ${SOURCES})