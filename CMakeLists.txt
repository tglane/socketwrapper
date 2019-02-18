cmake_minimum_required(VERSION 3.5.1)
project(socketwrapper VERSION 1.0.0)

set(CMAKE_CXX_STANDARD 11)

set(SOURCES_LIBRARY
        src/BaseSocket.cpp
        src/UDPSocket.cpp
        src/TCPSocket.cpp
        Exceptions/SocketCreationException.cpp
        Exceptions/SocketCloseException.cpp
        Exceptions/SocketBoundException.cpp
        Exceptions/SocketBindException.cpp
        )

set(LIBRARY_HEADERS
        src/BaseSocket.hpp
        src/UDPSocket.hpp
        src/TCPSocket.hpp
        )

add_library(${PROJECT_NAME} STATIC ${SOURCES_LIBRARY})

#[[install(TARGETS ${PROJECT_NAME} DESTINATION lib/)

set(SOURCES_TEST
	main.cpp
	src/BaseSocket.cpp
	src/UDPSocket.cpp
	src/TCPSocket.cpp
	Exceptions/SocketCreationException.cpp
	Exceptions/SocketCloseException.cpp
	Exceptions/SocketBoundException.cpp
	Exceptions/SocketBindException.cpp
	)

add_executable(socketwrapper_test ${SOURCES_TEST})]]
