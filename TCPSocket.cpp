//
// Created by timog on 23.12.18.
//

#include "TCPSocket.hpp"

namespace socketwrapper
{

TCPSocket::TCPSocket(int family)
{
    m_sockaddr_in = std::shared_ptr<sockaddr_in>(new sockaddr_in);
    m_sockaddr_in->sin_family = (sa_family_t) family;
    m_socktype = SOCK_DGRAM;
    m_family = family;

    if(family == AF_UNSPEC)
    {
        //Unable to create socket now
        return;
    }

    m_sockfd = ::socket(m_sockaddr_in->sin_family, m_socktype, 0);
    if(m_sockfd == -1)
    {
        //Error creating socket
        throw SocketCreationException();
    }

    int enabled = 1;
    ::setsockopt(m_sockfd, SOL_SOCKET, SO_REUSEADDR, &enabled, sizeof(int));

    m_created = true;
    m_closed = false;
}

TCPSocket::TCPSocket(int socket_fd, sockaddr_in own_addr, bool connected, bool bound)
{
    m_sockfd = socket_fd;
    m_sockaddr_in = std::shared_ptr<sockaddr_in>(new sockaddr_in);
    m_sockaddr_in->sin_addr.s_addr = own_addr.sin_addr.s_addr;
    m_sockaddr_in->sin_family = own_addr.sin_family;
    m_sockaddr_in->sin_port = own_addr.sin_port;
    m_connected = connected;
    m_bound = bound;
    m_created = true;
}

//TODO Fehler finden und beheben
void TCPSocket::listen(int queuesize)
{
    if(m_created && m_bound)
    {
        /**if((::listen(m_sockfd, queuesize)) == -1)
        {
            std::cout << "Error setting socket in listen mode" << std::endl;
            throw "Error setting socket in listen mode";
        }*/
        ::listen(m_sockfd, queuesize);
    }
}

void TCPSocket::connect(int port_to, in_addr_t addr_to)
{
    if(m_created && !m_connected) {
        struct sockaddr_in connect_to;
        connect_to.sin_port = htons((in_port_t) port_to);
        connect_to.sin_family = m_sockaddr_in->sin_family;
        connect_to.sin_addr.s_addr = addr_to;

        if ((::connect(m_sockfd, (struct sockaddr *) &connect_to, sizeof(sockaddr_in))) != 0) {
            std::cout <<"Error connecting to server" << std::endl;
            throw "Error connecting to server";
        }

        m_connected = true;
    }
}

std::shared_ptr<TCPSocket> TCPSocket::accept()
{
    if(m_bound && m_listening)
    {
        int new_sock;
        socklen_t cli_len = sizeof(struct sockaddr_in);
        new_sock = ::accept(m_sockfd, (sockaddr*) m_client_addr.get(), &cli_len);
        if(new_sock != 0)
        {
            std::cout << "Error accepting conection" << std::endl;
            throw "Error accepting connection";
        }

        return std::shared_ptr<TCPSocket>(new TCPSocket(new_sock, *m_sockaddr_in.get(), true, false));
    }
}

void TCPSocket::read(void *buff, size_t nbytes)
{
    int status = ::read(m_sockfd, buff, nbytes);
    if(status == -1)
    {
        std::cout << "Error receiving data" << std::endl;
        throw "Error receiving data";
    } else if(status == 0)
    {
        //Client wishes to close the connection
        close();
    }
}

void TCPSocket::write(const void *buff, size_t nbytes)
{
    int status = 0;
    size_t total_sent = 0;
    size_t bytes_left = nbytes;
    while(total_sent < nbytes)
    {
        status = ::write(m_sockfd, buff, bytes_left);
        if(status == -1)
        {
            std::cout << "Error sending data" << std::endl;
            throw "Error sending data - try again";
        } else
        {
            total_sent += status;
            bytes_left -= status;
        }
    }
}

}
