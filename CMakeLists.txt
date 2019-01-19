cmake_minimum_required(VERSION 3.5.1)
project(socketwrapper)

set(CMAKE_CXX_STANDARD 11)

set(SOURCES_LIBRARY
        BaseSocket.cpp
        UDPSocket.cpp
        TCPSocket.cpp
        Exceptions/SocketCreationException.cpp
        Exceptions/SocketCloseException.cpp
        Exceptions/SocketBoundException.cpp
        Exceptions/SocketBindException.cpp
        )

set(SOURCES_TEST
    main.cpp
    BaseSocket.cpp
    UDPSocket.cpp
    TCPSocket.cpp
    Exceptions/SocketCreationException.cpp
    Exceptions/SocketCloseException.cpp
    Exceptions/SocketBindException.cpp
    Exceptions/SocketBoundException.cpp
    )

add_library(socketwrapper SHARED ${SOURCES_LIBRARY})

add_executable(socketwrapper_test ${SOURCES_TEST})