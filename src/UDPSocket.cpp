//
// Created by timog on 23.12.18.
//

#include "UDPSocket.hpp"

namespace socketwrapper
{

UDPSocket::UDPSocket(int family)
{
    m_sockaddr_in.sin_family = (sa_family_t) family;
    m_socktype = SOCK_DGRAM;
    m_family = family;

    if(family == AF_UNSPEC)
    {
        //Unable to create a socket now
        return;
    }

    m_sockfd = socket(m_sockaddr_in.sin_family, m_socktype, 0);
    if(m_sockfd == -1)
    {
        throw SocketCreationException();
    }
    else
    {
        int reuse = 1;
        if (::setsockopt(m_sockfd, SOL_SOCKET, SO_REUSEADDR, (const char*)&reuse, sizeof(reuse)) < 0)
            perror("setsockopt(SO_REUSEADDR) failed");
        #ifdef SO_REUSEPORT

        if (::setsockopt(m_sockfd, SOL_SOCKET, SO_REUSEPORT, (const char*)&reuse, sizeof(reuse)) < 0) {
            throw "Error setsockopt";
        }
        #endif
        m_created = true;
        m_closed = false;
    }
}

char* UDPSocket::recvfrom(int bufflen)
{
    char* buffer_to;
    int bytes;

    buffer_to = new char[bufflen + 1];
    if(m_created && m_bound)
    {
        struct sockaddr_in from;
        socklen_t flen = sizeof(from);

        if((bytes = ::recvfrom(m_sockfd, buffer_to, (size_t) bufflen, 0, (struct sockaddr*) &from, &flen))  < 0)
        {
            //Error receivin data
            std::cout << "Error receiving data" << std::endl;
            throw "Error receiving data";
        }
    }
    buffer_to[bufflen] = '\0';
    return buffer_to;
}

void UDPSocket::sendto(const char* buffer_from, int port, in_addr_t addr)
{
    if(m_created) {
        struct sockaddr_in dest;
        dest.sin_family = (sa_family_t) m_family;
        dest.sin_port = htons((in_port_t) port);
        dest.sin_addr.s_addr = addr;

        if ((::sendto(m_sockfd, buffer_from, std::strlen(buffer_from), 0, (struct sockaddr *) &dest, sizeof(struct sockaddr_in))) == -1) {
            //Error sending data
            std::cout << "Error sending data" << std::endl;
            throw "Error sending data";
        }
    }
}

}
