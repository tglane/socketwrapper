//
// Created by timog on 23.12.18.
//

#include "../include/TCPSocket.hpp"

namespace socketwrapper
{

TCPSocket::TCPSocket(int family)
    : BaseSocket(family, SOCK_STREAM), m_client_addr{}, m_tcp_state(tcp_state::WAITING)
{}

TCPSocket::TCPSocket(int family, int socket_fd, sockaddr_in own_addr, int state, int tcp_state)
    : BaseSocket(family, SOCK_STREAM, socket_fd, own_addr, state), m_client_addr{}, m_tcp_state(tcp_state)
{}

TCPSocket::TCPSocket(TCPSocket&& other)
    : BaseSocket(std::move(other))
{
    *this = std::move(other);
}

TCPSocket& TCPSocket::operator=(TCPSocket&& other)
{
    BaseSocket::operator=(std::move(other));
    this->m_client_addr = other.m_client_addr;
    this->m_tcp_state = other.m_tcp_state;

    other.m_client_addr = sockaddr_in();
    other.m_tcp_state = tcp_state::WAITING;

    return *this;
}

void TCPSocket::close()
{
    if(m_socket_state != socket_state::CLOSED)
    {
        if (::close(m_sockfd) == -1) 
            throw SocketCloseException();
        else
        {
            m_socket_state = socket_state::CLOSED;
            m_tcp_state = tcp_state::WAITING;
        }
    }
}

void TCPSocket::listen(int queuesize)
{
    if (m_socket_state != socket_state::SHUT && m_tcp_state == tcp_state::WAITING)
    {
        if ((::listen(m_sockfd, queuesize)) != 0)
            throw SocketListenException();
        else
            m_tcp_state = tcp_state::LISTENING;
    }
    else
    {
        throw SocketListenException();
    }
}

void TCPSocket::connect(int port_to, in_addr_t addr_to)
{
    if(m_socket_state != socket_state::SHUT && m_tcp_state == tcp_state::WAITING)
    {
        sockaddr_in server = {};
        server.sin_family = AF_INET;
        server.sin_port = htons((in_port_t) port_to);
        server.sin_addr.s_addr = htonl(addr_to);

        if((::connect(m_sockfd, (sockaddr *) &server, sizeof(server))) != 0) 
            throw SocketConnectingException();
        else
            m_tcp_state = tcp_state::CONNECTED;
    }
    else
    {
        throw SocketConnectingException();
    }
}

void TCPSocket::connect(int port_to, std::string_view addr_to)
{
    in_addr_t in_addr{};
    inet_pton(m_family, addr_to.data(), &in_addr);

    TCPSocket::connect(port_to, ntohl(in_addr));
}

std::future<bool> TCPSocket::connect_async(int port, in_addr_t addr_to, const std::function<bool(TCPSocket&)>& callback)
{
    return std::async(std::launch::async, [this, port, addr_to, callback]() -> bool {
        this->connect(port, addr_to);
        return callback(*this);
    });
}

std::future<bool> TCPSocket::connect_async(int port, std::string_view addr_to, const std::function<bool(TCPSocket&)>& callback)
{
    return std::async(std::launch::async, [this, port, addr_to, callback]() -> bool {
        in_addr_t in_addr{};
        inet_pton(this->m_family, addr_to.data(), &in_addr);
            
        this->connect(port, ntohl(in_addr));
        return callback(*this);
    });
}

// std::future<bool> TCPSocket::connect_async_by_hostname(int port, const string& hostname, const std::function<bool(TCPSocket&)>& callback)
// {
//     return std::async(std::launch::async, [this, port, hostname, const 
// }

std::unique_ptr<TCPSocket> TCPSocket::accept()
{
    if(m_socket_state != socket_state::CLOSED && m_tcp_state == tcp_state::LISTENING)
    {

       socklen_t len = sizeof(m_client_addr);
        int conn_fd = ::accept(m_sockfd, (sockaddr *) &m_client_addr, &len);
        if(conn_fd < 0) 
            throw SocketAcceptingException();

        std::unique_ptr<TCPSocket> connSock(new TCPSocket(m_family, conn_fd, m_sockaddr_in, m_socket_state, tcp_state::ACCEPTED));
        return connSock;
    }
    else
    {
        throw SocketAcceptingException();
    }
}

std::future<bool> TCPSocket::accept_async(const std::function<bool(TCPSocket&)>& callback)
{
    return std::async(std::launch::async, [&]() {
        std::unique_ptr<TCPSocket> conn = this->accept();
        return callback(*conn);
    });
}

std::unique_ptr<char[]> TCPSocket::read(size_t size) const
{
    std::unique_ptr<char[]> buffer = std::make_unique<char[]>(size + 1);
    
    if(this->read_raw(buffer.get(), size) < 0)
        throw SocketReadException();

    return buffer;
}

std::vector<char> TCPSocket::read_vector(size_t size) const
{
    std::vector<char> buffer;
    buffer.reserve(size + 1);

    if(this->read_raw(buffer.data(), size) < 0)
        throw SocketReadException();
    
    return buffer;
}

void TCPSocket::write(const char* buffer, size_t size) const
{
    if(m_socket_state != socket_state::CLOSED && (m_tcp_state == tcp_state::ACCEPTED || m_tcp_state == tcp_state::CONNECTED))
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        /* Send the actual data */
        if(send(m_sockfd, buffer, size, 0) < 0)
            throw SocketWriteException();
    }
    else
        throw SocketWriteException();
}

void TCPSocket::write(const std::vector<char>& buffer) const
{
    this->write(buffer.data(), buffer.size());
}

std::unique_ptr<char[]> TCPSocket::read_all() const
{
    size_t available = bytes_available();
    std::unique_ptr<char[]> buffer = std::make_unique<char[]>(available + 1);

    if(this->read_raw(buffer.get(), available) < 0)
        throw SocketReadException();

    return buffer;
}

std::vector<char> TCPSocket::read_all_vector() const
{
    size_t available = bytes_available();
    std::vector<char> buffer;
    buffer.reserve(available + 1);
    
    if(this->read_raw(buffer.data(), available) < 0)
        throw SocketReadException();

    return buffer;
}

size_t TCPSocket::bytes_available() const
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

int TCPSocket::read_raw(char* const buffer, size_t size) const
{
    if(m_socket_state != socket_state::CLOSED && (m_tcp_state == tcp_state::ACCEPTED || m_tcp_state == tcp_state::CONNECTED))
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        if(::read(m_sockfd, buffer, size) < 0)
            throw SocketReadException();
        else
        {
            buffer[size] = '\0';
            return 0;
        }
    }
    
    return -1;
}

}
