//
// Created by timog on 23.12.18.
//

#include "../include/UDPSocket.hpp"

namespace socketwrapper
{

UDPSocket::UDPSocket(int family)
    : BaseSocket(family, SOCK_DGRAM)
{}

UDPSocket::UDPSocket(UDPSocket&& other)
    : BaseSocket(std::move(other))
{}

UDPSocket& UDPSocket::operator=(UDPSocket&& other)
{
    BaseSocket::operator=(std::move(other));
    return *this;
}

int UDPSocket::read_raw(char* const buffer, size_t size, sockaddr_in& from) const
{
    if(m_socket_state != socket_state::SHUT)
    {
        socklen_t flen = sizeof(from);
        std::lock_guard<std::mutex> lock(m_mutex);
        int ret = ::recvfrom(m_sockfd, buffer, size, 0, (struct sockaddr*) &from, &flen);
        if(ret < 0)
        {
            throw SocketReadException();
        }
        else if(ret > 0) 
        {
            buffer[ret] = '\0';
            return ret;
        }
    }

    return -1;
}

}

