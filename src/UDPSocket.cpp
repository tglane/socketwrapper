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

// void UDPSocket::send_to(const char* buffer_from, size_t size, int port, in_addr_t addr) const
// {
//     if(m_socket_state != socket_state::SHUT) {
//         struct sockaddr_in dest = {};
//         dest.sin_family = (sa_family_t) m_family;
//         dest.sin_port = htons((in_port_t) port);
//         dest.sin_addr.s_addr = addr;
// 
//         std::lock_guard<std::mutex> lock(m_mutex);
//         if ((::sendto(m_sockfd, buffer_from, size, 0, (struct sockaddr *) &dest, sizeof(struct sockaddr_in))) == -1) {
//             //Error sending data
//             throw SocketWriteException();
//         }
//     }
// }
// 
// void UDPSocket::send_to(const char *buffer_from, size_t size, int port, std::string_view addr) const
// {
//     in_addr_t inAddr{};
//     inet_pton(m_family, addr.data(), &inAddr);
//     this->send_to(buffer_from, size, port, inAddr);
// }

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

