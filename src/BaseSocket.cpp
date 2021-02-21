//
// Created by timog on 22.12.18.
//

#include <sys/ioctl.h>
#include "../include/BaseSocket.hpp"

namespace socketwrapper
{

BaseSocket::BaseSocket(ip_version family, sock_type sock_type)
    : m_sockfd {}, m_family {family}, m_socktype {sock_type}, m_sockaddr_in {}, m_socket_state {socket_state::SHUT}
{
    create_new_file_descriptor();
}

BaseSocket::BaseSocket(int socket_fd, ip_version family, sock_type sock_type, sockaddr_in own_addr, socket_state state)
    : m_sockfd {socket_fd}, m_family {family}, m_socktype {sock_type}, m_sockaddr_in {own_addr}, m_socket_state {state}
{}

BaseSocket::BaseSocket(BaseSocket&& other)
{
    *this = std::move(other);
}

BaseSocket::~BaseSocket()
{
    this->close();
}

BaseSocket& BaseSocket::operator=(BaseSocket&& other)
{
    this->m_sockfd = other.m_sockfd;
    this->m_socktype = other.m_socktype;
    this->m_family = other.m_family;
    this->m_socket_state = other.m_socket_state;

    other.m_sockfd = -1;
    other.m_socktype = sock_type::not_set;
    other.m_socket_state = socket_state::SHUT;

    return *this;
}

bool BaseSocket::create_new_file_descriptor()
{
    m_sockaddr_in.sin_family = {static_cast<uint8_t>(m_family)};

    m_sockfd = socket(m_sockaddr_in.sin_family, static_cast<int>(m_socktype), 0);
    if(m_sockfd == -1)
        throw SocketCreationException();

    int reuse = 1;
    if (::setsockopt(m_sockfd, SOL_SOCKET, SO_REUSEADDR, (const char*)&reuse, sizeof(reuse)) < 0) 
        throw SetSockOptException();

#ifdef SO_REUSEPORT
    if (::setsockopt(m_sockfd, SOL_SOCKET, SO_REUSEPORT, (const char*)&reuse, sizeof(reuse)) < 0) 
        throw SetSockOptException();
#endif

    m_socket_state = socket_state::CREATED;
    return true;
}

void BaseSocket::bind(const in_addr_t& address, int port)
{
    if(m_socket_state == socket_state::BOUND)
        throw SocketBoundException();

    m_sockaddr_in.sin_port = htons((in_port_t) port);
    m_sockaddr_in.sin_addr.s_addr = address;

    if((::bind(m_sockfd, (sockaddr*) &m_sockaddr_in, sizeof(struct sockaddr_in))) != 0)
        throw SocketBindException();
    else
        m_socket_state = socket_state::BOUND;
}

void BaseSocket::bind(std::string_view address, int port)
{
    in_addr_t inAddr{};
    inet_pton(static_cast<uint8_t>(m_family), address.data(), &inAddr);

    BaseSocket::bind(inAddr ,port);
}

void BaseSocket::close()
{
    if(m_socket_state != socket_state::CLOSED)
    {
        if (::close(m_sockfd) == -1) 
            throw SocketCloseException();
        else
            m_socket_state = socket_state::CLOSED;
    }
}

int BaseSocket::resolve_hostname(const char* host_name, sockaddr_in* addr_out) const
{
    int ret;
    addrinfo* resultList = NULL;
    addrinfo hints = {};
    int result = -1;

    hints.ai_family = static_cast<uint8_t>(m_family);
    hints.ai_socktype = static_cast<uint8_t>(m_socktype);

    ret = getaddrinfo(host_name, NULL, &hints, &resultList);

    result = (ret == 0) ? 1 : -1;
    if(result != -1)
    {
        *addr_out = *(sockaddr_in*)(resultList->ai_addr);
        result = 0;
    }
    
    if(resultList != NULL)
        ::freeaddrinfo(resultList);

    return result;    
}

size_t BaseSocket::bytes_available() const
{
    if(m_socket_state != socket_state::CLOSED)
    {
        int bytes;
        ioctl(m_sockfd, FIONREAD, &bytes);
        return bytes;
    }
    else
    {
        throw ReadBytesAvailableException();
    }
}

}
