//
// Created by timog on 22.12.18.
//

#ifndef SOCKETWRAPPER_BASESOCKET_HPP
#define SOCKETWRAPPER_BASESOCKET_HPP

#include <iostream>
#include <memory>
#include <cstring>
#include <string>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h> //for struct sockaddr_in
#include <netdb.h> //for struct addrinfo
#include <unistd.h> //for close(), ...
#include <arpa/inet.h> //for inet_addr()

#include "SocketCreationException.hpp"
#include "SocketCloseException.hpp"
#include "SocketBoundException.hpp"
#include "SocketBindException.hpp"
#include "SocketListenException.hpp"
#include "SocketConnectingException.hpp"
#include "SocketAcceptingException.hpp"
#include "SocketReadException.hpp"
#include "SocketWriteException.hpp"
#include "SetSockOptException.hpp"

using std::string;

namespace socketwrapper {

/**
 * Simple socket wrapper base class
 * Wraps the c socket functions into a c++ socket class
 */
class BaseSocket {

public:
    BaseSocket();

    ~BaseSocket();

    //Block copying
    BaseSocket(const BaseSocket& other) = delete;
    BaseSocket& operator=(const BaseSocket& other) = delete;

    /**
     * Binds the internal Socket to your local adress and the given port
     * @param port to bind the socket on this port of the host machine
     */
    void bind(string address, int port);

    /**
     * Closes the internal socket m_sockfd
     */
    void close();

protected:

    sockaddr_in m_sockaddr_in;

    int m_sockfd;

    int m_socktype;
    int m_family;

    bool m_bound = false;
    bool m_closed = true;
    bool m_created = false;

};

}

#endif //SOCKETWRAPPER_BASESOCKET_HPP
