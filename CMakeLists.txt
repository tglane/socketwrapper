cmake_minimum_required(VERSION 3.5.1)
project(socketwrapper VERSION 1.0.0)

set(CMAKE_CXX_STANDARD 17)

set(SOURCES_LIBRARY
        src/BaseSocket.cpp
        src/UDPSocket.cpp
        src/TCPSocket.cpp
        Exceptions/SocketCreationException.cpp
        Exceptions/SocketCloseException.cpp
        Exceptions/SocketBoundException.cppd
        Exceptions/SocketBindException.cpp
        )

file(GLOB SOURCES src/*.cpp Exceptions/*.cpp)

include_directories(include)

add_library(${PROJECT_NAME} SHARED ${SOURCES})

install(TARGETS ${PROJECT_NAME} DESTINATION lib/)

file(GLOB HEADERS include/*.hpp)
install(FILES ${HEADERS} DESTINATION include/${PROJECT_NAME})
