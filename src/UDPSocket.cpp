//
// Created by timog on 23.12.18.
//

#include "../include/UDPSocket.hpp"

namespace socketwrapper
{

UDPSocket::UDPSocket(int family)
    : BaseSocket{family, SOCK_DGRAM}
{
    m_sockaddr_in.sin_family = {(sa_family_t) family};

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
            throw SetSockOptException();
        }
        #endif
        m_created = true;
        m_closed = false;
    }
}

char* UDPSocket::receiveFrom(int bufflen)
{
    char* buffer_to;
    buffer_to = new char[bufflen + 1];

    if(m_created && m_bound)
    {
        struct sockaddr_in from = {};
        socklen_t flen = sizeof(from);
        int ret = ::recvfrom(m_sockfd, buffer_to, (size_t) bufflen, 0, (struct sockaddr*) &from, &flen);
        if(ret < 0)
        {
            throw SocketReadException();
        }
        else if(ret > 0) {
            buffer_to[bufflen] = '\0';
        }
    }
    return buffer_to;
}

vector<char> UDPSocket::receiveVector(int bufflen)
{
    char* buffer;

    buffer = this->receiveFrom(bufflen);

    vector<char> return_buffer{buffer, buffer + bufflen + 1};

    delete[] buffer;
    return return_buffer;
}

void UDPSocket::sendTo(const char* buffer_from, int port, in_addr_t addr)
{
    if(m_created) {
        struct sockaddr_in dest = {};
        dest.sin_family = (sa_family_t) m_family;
        dest.sin_port = htons((in_port_t) port);
        dest.sin_addr.s_addr = addr;

        if ((::sendto(m_sockfd, buffer_from, std::strlen(buffer_from), 0, (struct sockaddr *) &dest, sizeof(struct sockaddr_in))) == -1) {
            //Error sending data
            throw SocketWriteException();
        }
    }
}

void UDPSocket::sendTo(const char *buffer_from, int port, const string& addr)
{
    in_addr_t inAddr{};
    inet_pton(m_family, addr.c_str(), &inAddr);
    this->sendTo(buffer_from, port, inAddr);
}

void UDPSocket::sendTo(const vector<char>& buffer_from, int port, const string &addr)
{
    in_addr_t inAddr{};
    inet_pton(m_family, addr.c_str(), &inAddr);
    this->sendTo(buffer_from.data(), port, inAddr);
}

}
