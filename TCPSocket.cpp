//
// Created by timog on 23.12.18.
//

#include "TCPSocket.hpp"

namespace socketwrapper
{

TCPSocket::TCPSocket(int family)
{
    m_sockaddr_in.sin_family = (sa_family_t) family;
    m_socktype = SOCK_STREAM;
    m_family = family;

    if(family == AF_UNSPEC)
    {
        //Unable to create a socket now
        return;
    }

    if((m_sockfd = ::socket(family, SOCK_STREAM, 0)) == -1)
    {
        throw SocketCreationException();
    }
    else
    {
        m_created = true;
        m_closed = false;
    }
}

TCPSocket::TCPSocket(int socket_fd, sockaddr_in own_addr, bool accepted, bool bound)
{
    m_sockfd = socket_fd;
    m_sockaddr_in = own_addr;
    m_accepted = accepted;
    m_bound = bound;
    m_created = true;
    m_closed = false;
    m_listening = false;
    m_connected = false;
}

void TCPSocket::listen(int queuesize)
{
    if((::listen(m_sockfd, queuesize)) != 0)
    {
        std::cout << "Error setting socket in listening mode" << std::endl;
        throw "Error setting socket in listening mode";
    }
    else
    {
        m_listening = true;
    }
}

void TCPSocket::connect(int port_to, in_addr_t addr_to)
{
    sockaddr_in server;
    server.sin_family = AF_INET;
    server.sin_port = htons((in_port_t) port_to);
    server.sin_addr.s_addr = htonl(addr_to);

    if((::connect(m_sockfd, (sockaddr*) &server, sizeof(server))) != 0)
    {
        std::cout << "Error connecting" << std::endl;
        throw "Error connecting";
    }
    else
    {
        m_connected = true;
    }
}

std::shared_ptr<TCPSocket> TCPSocket::accept()
{
    socklen_t len = sizeof(m_client_addr);
    int conn_fd = ::accept(m_sockfd, (sockaddr*) &m_client_addr, &len);
    if(conn_fd < 0)
    {
        std::cout << "Error accepting connection";
        throw "Error accepting connection";
    }

    std::shared_ptr<TCPSocket> connSock(new TCPSocket(conn_fd, m_sockaddr_in, true, false));
    return connSock;
}

void TCPSocket::read(void *buff)
{
    if(m_connected || m_accepted)
    {
        ::read(m_sockfd, buff, sizeof(buff));
    }
    else
    {
        throw "Socket not connected or accepted - can't read";
    }
}

void TCPSocket::write(const void *buff)
{
    if(m_connected || m_accepted)
    {
        ::write(m_sockfd, buff, sizeof(buff));
    }
    else
    {
        throw "Socket not connected or accepted - can't write";
    }
}

}
