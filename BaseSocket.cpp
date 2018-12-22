//
// Created by timog on 22.12.18.
//

#include "BaseSocket.hpp"

namespace socketwrapper
{

BaseSocket::BaseSocket()
{
    //m_sock_addr = std::make_shared<addrinfo>(new struct addrinfo);
    m_sock_addr = new addrinfo;
    m_sock_addr->ai_family = AF_UNSPEC;
    m_sock_addr->ai_socktype = 0;

    //Unable to create a socket now
}

BaseSocket::BaseSocket(int family, int socktype, int flags)
{
    //m_sock_addr = std::make_shared<addrinfo>(new struct addrinfo);
    m_sock_addr = new addrinfo;
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
    delete m_sock_addr;
}

void BaseSocket::bind(int port)
{
    if(m_bound)
    {
        throw "Already bound";
    }

    addrinfo* result;
    getaddrinfo(NULL, port, &m_sock_addr, &result);

    if((bind(m_sockfd, )))
}

void BaseSocket::connect(std::string adress, int port)
{

}

void BaseSocket::listen(int queue)
{

}

std::shared_ptr<BaseSocket> BaseSocket::accept()
{

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