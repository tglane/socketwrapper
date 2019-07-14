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
        m_socket_state = socket_state::CREATED;
    }
}

std::unique_ptr<char[]> UDPSocket::receive_from(int bufflen)
{
    std::unique_ptr<char[]> buffer_to = std::make_unique<char[]>(bufflen + 1);

    if(m_socket_state != socket_state::CLOSED)
    {
        struct sockaddr_in from = {};
        socklen_t flen = sizeof(from);
        int ret = ::recvfrom(m_sockfd, buffer_to.get(), (size_t) bufflen, 0, (struct sockaddr*) &from, &flen);
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

vector<char> UDPSocket::receive_vector(int bufflen)
{
    std::unique_ptr<char[]> buffer = this->receive_from(bufflen);
    vector<char> return_buffer(buffer.get(), buffer.get() + bufflen + 1);

    return return_buffer;
}

void UDPSocket::send_to(const char* buffer_from, int port, in_addr_t addr)
{
    if(m_socket_state != socket_state::CLOSED) {
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

void UDPSocket::send_to(const char *buffer_from, int port, const string& addr)
{
    in_addr_t inAddr{};
    inet_pton(m_family, addr.c_str(), &inAddr);
    this->send_to(buffer_from, port, inAddr);
}

void UDPSocket::send_to(const vector<char>& buffer_from, int port, const string &addr)
{
    in_addr_t inAddr{};
    inet_pton(m_family, addr.c_str(), &inAddr);
    this->send_to(buffer_from.data(), port, inAddr);
}

}
