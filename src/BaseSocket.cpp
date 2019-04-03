//
// Created by timog on 22.12.18.
//

#include "../include/BaseSocket.hpp"

namespace socketwrapper
{

BaseSocket::BaseSocket()
{

    //Unable to create a socket now
}

BaseSocket::~BaseSocket()
{
    if(!m_closed)
    {
        close();
    }
}

void BaseSocket::bind(string address, int port)
{
    if(m_bound)
    {
        throw SocketBoundException();
    }

    m_sockaddr_in.sin_port = htons((in_port_t) port);
    m_sockaddr_in.sin_addr.s_addr = htonl(inet_addr(address.c_str()));

    if((::bind(m_sockfd, (sockaddr*) &m_sockaddr_in, sizeof(struct sockaddr_in))) != 0)
    {
        std::cout << "Fehler bei bind" << std::endl;
        throw SocketBindException();
    }
    else
    {
        m_bound = true;
    }
}

void BaseSocket::close()
{
    if(!m_closed)
    {
        if (::close(m_sockfd) == -1) {
            throw SocketCloseException();
        } else {
            m_closed = true;
        }
    }
}

}
