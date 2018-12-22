//
// Created by timog on 22.12.18.
//

#include "BaseSocket.hpp"

namespace socketwrapper
{

BaseSocket::BaseSocket()
{
    m_sock_addr = std::make_shared<addrinfo>(new addrinfo);
    m_sock_addr->ai_family = AF_UNSPEC;
    m_sock_addr->ai_socktype = 0;

    //Unable to create a socket now
}

BaseSocket::BaseSocket(int family, int socktype, int flags)
{
    m_sock_addr = std::make_shared<addrinfo>(new addrinfo);
    m_sock_addr->ai_family = family;
    m_sock_addr->ai_socktype = socktype;
    m_sock_addr->ai_flags = flags;

    if(family == AF_UNSPEC)
    {
        //Unable to create a socket now
        return;
    }

    m_sockfd = socket(m_sock_addr->ai_family, m_sock_addr->ai_socktype, 0);
    if(m_sockfd == -1)
    {
        throw SocketCreationException();
    }

    m_created = true;
    m_closed = false;
}

BaseSocket::~BaseSocket()
{
    if(!m_closed)
    {
        close();
    }
}

void BaseSocket::close()
{
    if(::close(m_sockfd) == -1)
    {
        throw SocketCloseException();
    } else
    {
        m_closed = true;
    }
}

}