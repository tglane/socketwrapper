//
// Created by timog on 22.12.18.
//

#ifndef SOCKETWRAPPER_BASESOCKET_HPP
#define SOCKETWRAPPER_BASESOCKET_HPP

#include <iostream>
#include <memory>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h> //for struct sockaddr_in
#include <netdb.h> //for struct addrinfo
#include <unistd.h> //for close

#include "Exceptions/SocketCreationException.hpp"
#include "Exceptions/SocketCloseException.hpp"

namespace socketwrapper {

/**
 * Simple Socket wrapper class
 * Wraps the c socket functions into a c++ socket class
 */
class BaseSocket {

public:

    BaseSocket();

    BaseSocket(int family, int socktype, int flags);

    ~BaseSocket();

    void close();

private:

    std::shared_ptr<addrinfo> m_sock_addr;

    int m_sockfd;

    bool m_connected = false;
    bool m_bound = false;
    bool m_closed = true;
    bool m_created = false;

};

}

#endif //SOCKETWRAPPER_BASESOCKET_HPP
