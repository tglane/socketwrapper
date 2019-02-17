//
// Created by timog on 23.12.18.
//

#ifndef SOCKETWRAPPER_TCPSOCKET_HPP
#define SOCKETWRAPPER_TCPSOCKET_HPP

#include "BaseSocket.hpp"

namespace socketwrapper
{

/**
 * Simple tcp socket class wrapping the c socket to a c++ class
 * Only for tcp sockets
 */
class TCPSocket : public BaseSocket
{

public:

    using Ptr = std::shared_ptr<TCPSocket>;

    TCPSocket(int family);

    /**
     * Sets the internal socket in listening mode
     * @param queuesize max number of clients waiting for establishing a connection
     */
    void listen(int queuesize = 5);

    /**
     * Establishes a connection to a server
     * @param port_to port of the server to connect to
     * @param addr_to ip address of the server to connect to
     */
    void connect(int port_to, in_addr_t addr_to);

    /**
     * Waits for a client to connect to the socket
     * Usable only after call of listen() and m_listeing and m_bound true
     * @return shared_ptr<TCPSocket> to handle the established connection
     */
    std::shared_ptr<TCPSocket> accept();

    /**
     * Reads the content sended by a client and stores it into a buffer
     * @param buff buffer to store the given content in
     */
    char* read();

    /**
     * Sends the content of a buffer to connected client
     * @param buff buffer with the content to send
     */
    void write(const char* buffer);

    void printThings() {std::cout << m_accepted << m_sockfd << std::endl;}

protected:

    TCPSocket(int socket_fd, sockaddr_in own_addr, bool accepted, bool bound);

    /// Stores the address of a connected client
    /// Only set if the socket is in "server mode" and a client is connected
    sockaddr_in m_client_addr;

    bool m_connected = false;
    bool m_listening = false;
    bool m_accepted = false;

};

}

#endif //SOCKETWRAPPER_TCPSOCKET_HPP
