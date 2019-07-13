//
// Created by timog on 23.12.18.
//

#include "../include/TCPSocket.hpp"

namespace socketwrapper
{

TCPSocket::TCPSocket(int family)
    : BaseSocket(family, SOCK_STREAM), m_client_addr{}
{
    m_sockaddr_in.sin_family = (sa_family_t) family;

    if(family == AF_UNSPEC)
    {
        //Unable to create a socket now
        return;
    }

    if((m_sockfd = ::socket(family, SOCK_STREAM, 0)) == -1)
    {
        throw SocketCreationException();
    }
    else
    {
        int reuse = 1;
        if (setsockopt(m_sockfd, SOL_SOCKET, SO_REUSEADDR, (const char*)&reuse, sizeof(reuse)) < 0)
            perror("setsockopt(SO_REUSEADDR) failed");
#ifdef SO_REUSEPORT
        if (setsockopt(m_sockfd, SOL_SOCKET, SO_REUSEPORT, (const char*)&reuse, sizeof(reuse)) < 0) {
            throw SetSockOptException();
        }
#endif
        m_created = true;
        m_closed = false;
    }
}

TCPSocket::TCPSocket(int family, int socket_fd, sockaddr_in own_addr, bool bound, bool accepted)
    : BaseSocket{family, SOCK_STREAM, socket_fd, own_addr, bound}, m_client_addr{}, m_accepted{accepted}, m_listening{false}, m_connected{false}
{
    m_created = true;
    m_closed = false;
}

void TCPSocket::listen(int queuesize)
{
    if((::listen(m_sockfd, queuesize)) != 0)
    {
        std::cout << "Error setting socket in listening mode" << std::endl;
        throw SocketListenException();
    }
    else
    {
        m_listening = true;
    }
}

void TCPSocket::connect(int port_to, in_addr_t addr_to)
{
    sockaddr_in server = {};
    server.sin_family = AF_INET;
    server.sin_port = htons((in_port_t) port_to);
    server.sin_addr.s_addr = htonl(addr_to);

    if((::connect(m_sockfd, (sockaddr*) &server, sizeof(server))) != 0)
    {
        throw SocketConnectingException();
    }
    else
    {
        m_connected = true;
    }
}

void TCPSocket::connect(int port_to, const string &addr_to)
{
    in_addr_t inAddr{};
    inet_pton(m_family, addr_to.c_str(), &inAddr);
    TCPSocket::connect(port_to, inAddr);
}

std::unique_ptr<TCPSocket> TCPSocket::accept()
{
    socklen_t len = sizeof(m_client_addr);
    int conn_fd = ::accept(m_sockfd, (sockaddr*) &m_client_addr, &len);
    if(conn_fd < 0)
    {
        throw SocketAcceptingException();
    }

    std::unique_ptr<TCPSocket> connSock(new TCPSocket(m_family, conn_fd, m_sockaddr_in, false, true));
    return connSock;
}

std::unique_ptr<char[]> TCPSocket::read(unsigned int size)
{
    std::unique_ptr<char[]> buffer = std::make_unique<char[]>(size + 1);
    if(m_connected || m_accepted) {
        /* Read the data */
        int ret = ::read(m_sockfd, buffer.get(), size);
        if(ret < 0)
        {
            throw SocketReadException();
        }
        else if(ret > 0) {
            buffer[size] = '\0'; //Null-terminate the String -> '' declares a char --- "" declares a String
        }
    }
    return buffer;
}

vector<char> TCPSocket::readVector(unsigned int size)
{
    std::unique_ptr<char[]> buffer = this->read(size);
    vector<char> buffer_vector(buffer.get(), buffer.get() + size + 1);

    return buffer_vector;
}

void TCPSocket::write(const char *buffer)
{
    if(m_connected || m_accepted)
    {
        /* Send the actual data */
        if(send(m_sockfd, buffer, std::strlen(buffer), 0) < 0)
        {
            throw SocketWriteException();
        }
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
    if(m_connected || m_accepted)
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

    if(m_connected || m_accepted)
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
    int bytes;
    ioctl(m_sockfd, FIONREAD, &bytes);
    return bytes;
}

}
