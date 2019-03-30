//
// Created by timog on 23.12.18.
//

#include "../include/TCPSocket.hpp"
#include <iostream>

namespace socketwrapper
{

TCPSocket::TCPSocket(int family)
{
    m_sockaddr_in.sin_family = (sa_family_t) family;
    m_socktype = SOCK_STREAM;
    m_family = family;

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
            throw "Error setsockopt";
        }
        #endif
        m_created = true;
        m_closed = false;
    }
}

TCPSocket::TCPSocket(int socket_fd, sockaddr_in own_addr, bool accepted, bool bound)
{
    m_sockfd = socket_fd;
    m_sockaddr_in = own_addr;
    m_accepted = accepted;
    m_bound = bound;
    m_created = true;
    m_closed = false;
    m_listening = false;
    m_connected = false;
}

void TCPSocket::listen(int queuesize)
{
    if((::listen(m_sockfd, queuesize)) != 0)
    {
        std::cout << "Error setting socket in listening mode" << std::endl;
        throw "Error setting socket in listening mode";
    }
    else
    {
        m_listening = true;
    }
}

void TCPSocket::connect(int port_to, in_addr_t addr_to)
{
    sockaddr_in server;
    server.sin_family = AF_INET;
    server.sin_port = htons((in_port_t) port_to);
    server.sin_addr.s_addr = htonl(addr_to);

    if((::connect(m_sockfd, (sockaddr*) &server, sizeof(server))) != 0)
    {
        std::cout << "Error connecting" << std::endl;
        throw "Error connecting";
    }
    else
    {
        m_connected = true;
    }
}

std::shared_ptr<TCPSocket> TCPSocket::accept()
{
    socklen_t len = sizeof(m_client_addr);
    int conn_fd = ::accept(m_sockfd, (sockaddr*) &m_client_addr, &len);
    if(conn_fd < 0)
    {
        std::cout << "Error accepting connection";
        throw "Error accepting connection";
    }

    std::shared_ptr<TCPSocket> connSock(new TCPSocket(conn_fd, m_sockaddr_in, true, false));
    return connSock;
}

char* TCPSocket::read(unsigned int size)
{
    char *buffer;
    buffer = new char[size + 1];
    if(m_connected || m_accepted) {
        /* Read the data */
        if(::read(m_sockfd, buffer, size) < 0)
        {
            throw "Error transmitting data";
        }

        buffer[size] = '\0'; //Null-terminate the String -> '' declares a char --- "" declares a String
    }
    return buffer;
}

void TCPSocket::write(const char *buffer)
{
    if(m_connected || m_accepted)
    {
        /* Send the actual data */
        if(send(m_sockfd, buffer, std::strlen(buffer), 0) < 0)
        {
            throw "Error sending the data";
        }
    }
}

char* TCPSocket::readAll()
{
    unsigned int available = bytes_available();
    char* buffer;
    buffer = new char[available + 1];
    if(m_connected || m_accepted)
    {
        if(::read(m_sockfd, buffer, available) < 0)
        {
            throw "Error reading data";
        }
        buffer[available] = '\0'; //Null-terminating the string
    }
    return buffer;
}

unsigned int TCPSocket::bytes_available()
{
    unsigned int bytes;
    ioctl(m_sockfd, FIONREAD, &bytes);
    return bytes;
}

}
