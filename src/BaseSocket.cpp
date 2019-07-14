//
// Created by timog on 22.12.18.
//

#include "../include/BaseSocket.hpp"

namespace socketwrapper
{

BaseSocket::BaseSocket(int family, int sock_type)
    : m_family(family), m_socktype(sock_type), m_sockaddr_in{}, m_sockfd{}, m_socket_state(socket_state::CLOSED)
{
    //Unable to create a socket now
}

BaseSocket::BaseSocket(int family, int sock_type, int socket_fd, sockaddr_in own_addr, int state)
    : m_family(family), m_socktype(sock_type), m_sockfd(socket_fd), m_sockaddr_in(own_addr), m_socket_state(state)
{}

BaseSocket::~BaseSocket()
{
    this->close();
}

void BaseSocket::bind(const in_addr_t& address, int port)
{
    if(m_socket_state == socket_state::BOUND)
    {
        throw SocketBoundException();
    }

    m_sockaddr_in.sin_port = htons((in_port_t) port);
    m_sockaddr_in.sin_addr.s_addr = address;

    if((::bind(m_sockfd, (sockaddr*) &m_sockaddr_in, sizeof(struct sockaddr_in))) != 0)
    {
        throw SocketBindException();
    }
    else
    {
        m_socket_state = socket_state::BOUND;
    }
}

void BaseSocket::bind(const string &address, int port)
{
    BaseSocket::bind(htonl(inet_addr(address.c_str())) ,port);
}

void BaseSocket::close()
{
    if(m_socket_state != socket_state::CLOSED)
    {
        if (::close(m_sockfd) == -1) {
            throw SocketCloseException();
        } else {
            m_socket_state = socket_state::CLOSED;
        }
    }
}

}
