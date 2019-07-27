//
// Created by timog on 22.12.18.
//

#ifndef SOCKETWRAPPER_BASESOCKET_HPP
#define SOCKETWRAPPER_BASESOCKET_HPP

#include <memory>
#include <cstring>
#include <string>
#include <vector>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h> //for struct sockaddr_in
#include <netdb.h> //for struct addrinfo
#include <unistd.h> //for close(), ...
#include <arpa/inet.h> //for inet_addr()

#include "BaseException.hpp"

using std::string;
using std::vector;

namespace socketwrapper {

/**
 * @brief Simple socket wrapper base class that wraps the c socket functions into a c++ socket class
 */
class BaseSocket
{

public:

    BaseSocket() = delete;

    virtual ~BaseSocket();

    //Block copying
    BaseSocket(const BaseSocket& other) = delete;
    BaseSocket& operator=(const BaseSocket& other) = delete;

    /**
     * Binds the internal Socket to your local adress and the given port
     * @param port to bind the socket on this port of the host machine
     * @throws SocketBoundException SocketBindException
     */
    void bind(const in_addr_t& address, int port);

    void bind(const string& address, int port);

    /**
     * @brief Closes the internal socket filedescriptor m_sockfd
     * @throws SocketCloseException
     */
    virtual void close();

    /**
     * @brief Returns the underlying socket descriptor to use it without the wrapping class
     * @return int
     */
    int get_socket_descriptor()  { return m_sockfd; }

protected:

    BaseSocket(int family, int sock_type);

    BaseSocket(int family, int sock_type, int socket_fd, sockaddr_in own_addr, int state);

    /**
     * Sets the internal socket file descriptor
     * @param int family
     * @param int sock_type
     * @return bool
     * @throws SocketCreationException SetSockOptException
     */
    bool create_new_file_descriptor();

    sockaddr_in m_sockaddr_in;

    int m_sockfd;

    int m_socktype;
    int m_family;

    int m_socket_state;
    enum socket_state {SHUT, CLOSED, CREATED, BOUND};

};

}

#endif //SOCKETWRAPPER_BASESOCKET_HPP
