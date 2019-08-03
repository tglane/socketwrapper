cmake_minimum_required(VERSION 3.5.1)
project(socketwrapper VERSION 1.0.0)

set(CMAKE_CXX_STANDARD 17)

set(SOURCES_LIBRARY
        src/BaseSocket.cpp
        src/UDPSocket.cpp
        src/TCPSocket.cpp
        src/SSLTCPSocket.cpp
        )

find_package(OpenSSL REQUIRED)
if(OPENSSL_FOUND)
    link_directories(${OPENSSL_LIBRARIES})
    include_directories(${OPENSSL_INCLUDE_DIR})
endif(OPENSSL_FOUND)

file(GLOB SOURCES src/*.cpp)
include_directories(include)

add_library(socketwrapper_shared SHARED ${SOURCES})
target_link_libraries(socketwrapper_shared ${OPENSSL_LIBRARIES})

add_library(socketwrapper_static STATIC ${SOURCES})
target_link_libraries(socketwrapper_static ${OPENSSL_LIBRARIES})

install(TARGETS socketwrapper_shared DESTINATION lib/)
file(GLOB HEADERS include/*.hpp)
install(FILES ${HEADERS} DESTINATION include/${PROJECT_NAME})
