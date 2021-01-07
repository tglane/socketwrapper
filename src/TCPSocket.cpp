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

std::unique_ptr<TCPSocket> TCPSocket::accept() const 
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

std::future<bool> TCPSocket::accept_async(const std::function<bool(TCPSocket&)>& callback) const
{
    return std::async(std::launch::async, [&]() {
        std::unique_ptr<TCPSocket> conn = this->accept();
        return callback(*conn);
    });
}

void TCPSocket::write(const std::string& buffer) const
{
    this->write_raw(buffer.data(), buffer.size());
}

void TCPSocket::write(std::string_view buffer) const
{
    this->write_raw(buffer.data(), buffer.size());
}

std::string TCPSocket::read_string(size_t size) const
{
    std::string buffer;
    buffer.resize(size + 1);
    
    int bytes = this->read_raw((char*) buffer.data(), size, nullptr);
    if(bytes < 0)
        throw SocketReadException();
  
    if(buffer[bytes - 1] != '\0')
    {
        buffer.resize(bytes + 1);
        buffer[bytes] = '\0';
    }
    else
    {
        buffer.resize(bytes);
    }

    return buffer;
}

std::string TCPSocket::read_string(size_t size, const timeval& timeout) const
{
    std::string buffer;
    buffer.resize(size + 1);

    int bytes = this->read_raw((char*) buffer.data(), size, &timeout);
    if(bytes < 0)
        throw SocketReadException();

    if(buffer[bytes - 1] != '\0')
    {
        buffer.resize(bytes + 1);
        buffer[bytes] = '\0';
    }
    else
    {
        buffer.resize(bytes);
    }

    return buffer;
}

std::future<std::string> TCPSocket::read_string_async(size_t size) const
{
    return std::async(std::launch::async, [this, size]() -> std::string
    {
        std::string buffer;
        buffer.resize(size + 1);

        int bytes = this->read_raw((char*) buffer.data(), size);
        if(bytes < 0)
            return "";
        
        if(buffer[bytes - 1] != '\0')
        {
            buffer.resize(bytes + 1);
            buffer[bytes] = '\0';
        }
        else
        {
            buffer.resize(bytes);
        }
        return buffer;
    });
}

std::future<bool> TCPSocket::read_string_async(size_t size, const std::function<void(const std::string&)>& callback) const
{
    return std::async(std::launch::async, [this, size, &callback]() -> bool
    {
        std::string buffer;
        try {
            buffer = this->read_string(size);
        } catch(SocketReadException&) {
            return false;
        }

        callback(buffer);
        return true;
    });
}

int TCPSocket::read_raw(char* const buffer, size_t size, const timeval* timeout) const
{
    if(m_socket_state != socket_state::CLOSED && (m_tcp_state == tcp_state::ACCEPTED || m_tcp_state == tcp_state::CONNECTED))
    {
        fd_set fds;
        FD_ZERO(&fds);
        FD_SET(m_sockfd, &fds); 

        int rec_fd = select(m_sockfd + 1, &fds, nullptr, nullptr, const_cast<timeval*>(timeout));
        switch(rec_fd)
        {
            case(0): // Timeout
            case(-1): // Error
                return -1;
            default:
            {
                std::lock_guard<std::mutex> lock(m_mutex);
                size_t bytes = ::read(m_sockfd, buffer, size);
                if(bytes < 0)
                    throw SocketReadException();
                return bytes;
            }
        }
    }
    
    return -1;
}

void TCPSocket::write_raw(const char* buffer, size_t size) const
{
    if(m_socket_state != socket_state::CLOSED && (m_tcp_state == tcp_state::ACCEPTED || m_tcp_state == tcp_state::CONNECTED))
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        /* Send the actual data */
        if(send(m_sockfd, buffer, size, 0) < 0)
            throw SocketWriteException();
    }
    else
    {
        throw SocketWriteException();
    }
}

}
