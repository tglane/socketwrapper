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

void UDPSocket::recvfrom(void* buffer_to)
{
    if(m_created && m_bound)
    {
        struct sockaddr_in from;
        socklen_t flen = sizeof(from);

        if((::recvfrom(m_sockfd, buffer_to, sizeof(buffer_to), 0, (struct sockaddr*) &from, &flen))  < 0)
        {
            //Error receivin data
            std::cout << "Error receiving data" << std::endl;
            throw "Error receiving data";
        }
    }
}

void UDPSocket::sendto(const void* buffer_from, size_t nbytes, int port, in_addr_t addr)
{
    if(m_created) {
        struct sockaddr_in dest;
        dest.sin_family = (sa_family_t) m_family;
        dest.sin_port = htons((in_port_t) port);
        dest.sin_addr.s_addr = addr;

        if ((::sendto(m_sockfd, buffer_from, nbytes, 0, (struct sockaddr *) &dest, sizeof(struct sockaddr_in))) == -1) {
            //Error sending data
            std::cout << "Error sending data" << std::endl;
            throw "Error sending data";
        }
    }
}

}
