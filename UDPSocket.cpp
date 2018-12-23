//
// Created by timog on 23.12.18.
//

#include "UDPSocket.hpp"

namespace socketwrapper
{

UDPSocket::UDPSocket(int family)
{
    m_sockaddr_in = std::shared_ptr<sockaddr_in>(new sockaddr_in);
    m_sockaddr_in->sin_family = (sa_family_t) family;
    m_socktype = SOCK_DGRAM;
    m_family = family;

    if(family == AF_UNSPEC)
    {
        //Unable to create a socket now
        return;
    }

    m_sockfd = socket(m_sockaddr_in->sin_family, m_socktype, 0);
    if(m_sockfd == -1)
    {
        throw SocketCreationException();
    }

    m_created = true;
    m_closed = false;
}

void UDPSocket::recvfrom(void* buffer_to, size_t nbytes)
{

}

void UDPSocket::sendto(const void* buffer_from, size_t nbytes)
{

}

}