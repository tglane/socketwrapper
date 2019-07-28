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

void TCPSocket::close()
{
    if(m_socket_state != socket_state::CLOSED)
    {
        if (::close(m_sockfd) == -1) {
            throw SocketCloseException();
        } else {
            m_socket_state = socket_state::CLOSED;
            m_tcp_state = tcp_state::WAITING;
        }
    }
}

void TCPSocket::listen(int queuesize)
{
    if (m_socket_state != socket_state::SHUT && m_tcp_state == tcp_state::WAITING)
    {
        if ((::listen(m_sockfd, queuesize)) != 0) {
            throw SocketListenException();
        } else {
            m_tcp_state = tcp_state::LISTENING;
        }
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

        if ((::connect(m_sockfd, (sockaddr *) &server, sizeof(server))) != 0) {
            throw SocketConnectingException();
        } else {
            m_tcp_state = tcp_state::CONNECTED;
        }
    }
    else
    {
        throw SocketConnectingException();
    }
}

void TCPSocket::connect(int port_to, const string &addr_to)
{
    in_addr_t inAddr{};
    inet_pton(m_family, addr_to.c_str(), &inAddr);

    TCPSocket::connect(port_to, ntohl(inAddr));
}

std::unique_ptr<TCPSocket> TCPSocket::accept()
{
    if(m_socket_state != socket_state::CLOSED && m_tcp_state == tcp_state::LISTENING)
    {

        socklen_t len = sizeof(m_client_addr);
        int conn_fd = ::accept(m_sockfd, (sockaddr *) &m_client_addr, &len);
        if (conn_fd < 0) {
            throw SocketAcceptingException();
        }

        std::unique_ptr<TCPSocket> connSock(new TCPSocket(m_family, conn_fd, m_sockaddr_in, m_socket_state, tcp_state::ACCEPTED));
        return connSock;
    }
    else
    {
        throw SocketAcceptingException();
    }
}

std::unique_ptr<char[]> TCPSocket::read(unsigned int size)
{
    //std::unique_ptr<char[]> buffer = std::make_unique<char[]>(size + 1);
    char buffer[size +1];
    int ret {};
    if(m_socket_state != socket_state::CLOSED && (m_tcp_state == tcp_state::ACCEPTED || m_tcp_state == tcp_state::CONNECTED)) {
        /* Read the data */
        ret = ::read(m_sockfd, &buffer, size);
        if(ret < 0)
        {
            throw SocketReadException();
        }
        else if(ret > 0) {
            buffer[size] = '\0'; //Null-terminate the String -> '' declares a char --- "" declares a String
        }
    }
    auto ret_buffer = std::make_unique<char[]>(ret);
    std::copy(buffer, buffer + ret, ret_buffer.get());
    return ret_buffer;
}

vector<char> TCPSocket::read_vector(unsigned int size)
{
    //TODO implement without heap allocation
    std::unique_ptr<char[]> buffer = this->read(size);
    vector<char> buffer_vector(buffer.get(), buffer.get() + size + 1);

    return buffer_vector;
}

void TCPSocket::write(const char *buffer)
{
    if(m_socket_state != socket_state::CLOSED && (m_tcp_state == tcp_state::ACCEPTED || m_tcp_state == tcp_state::CONNECTED))
    {
        /* Send the actual data */
        if(send(m_sockfd, buffer, std::strlen(buffer), 0) < 0)
        {
            throw SocketWriteException();
        }
    }
    else
    {
        throw SocketWriteException();
    }
}

void TCPSocket::write(const vector<char>& buffer)
{
    this->write(buffer.data());
}

std::unique_ptr<char[]> TCPSocket::read_all()
{
    int available = bytes_available();
    std::unique_ptr<char[]> buffer = std::make_unique<char[]>(available + 1);

    if(m_socket_state != socket_state::CLOSED && (m_tcp_state == tcp_state::ACCEPTED || m_tcp_state == tcp_state::CONNECTED))
    {
        int ret = ::read(m_sockfd, buffer.get(), available);
        if(ret < 0)
        {
            throw SocketReadException();
        }
        else if(ret > 0) {
            buffer[available] = '\0'; //Null-terminating the string
        }
    }
    return buffer;
}

vector<char> TCPSocket::read_all_vector()
{
    int available = bytes_available();
    std::unique_ptr<char[]> buffer = std::make_unique<char[]>(available + 1);

    if(m_socket_state != socket_state::CLOSED && (m_tcp_state == tcp_state::ACCEPTED || m_tcp_state == tcp_state::CONNECTED))
    {
        int ret = ::read(m_sockfd, buffer.get(), available);
        if(ret < 0)
        {
            throw SocketReadException();
        }
        else if(ret > 0) {
            buffer[available] = '\0'; //Null-terminating the string
        }
    }

    vector<char> buffer_return(buffer.get(), buffer.get() + available +1);
    return buffer_return;
}

int TCPSocket::bytes_available()
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
