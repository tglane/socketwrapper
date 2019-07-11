//
// Created by timog on 23.12.18.
//

#ifndef SOCKETWRAPPER_TCPSOCKET_HPP
#define SOCKETWRAPPER_TCPSOCKET_HPP

#include <sys/ioctl.h>

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

    explicit TCPSocket(int family);

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
    virtual void connect(int port_to, in_addr_t addr_to);

    virtual void connect(int port_to, const string& addr_to);

    /**
     * Waits for a client to connect to the socket
     * Usable only after call of listen() and m_listeing and m_bound true
     * @return shared_ptr<TCPSocket> to handle the established connection
     */
    std::shared_ptr<TCPSocket> acceptShared();

    std::unique_ptr<TCPSocket> acceptUnique();

    /**
     * Reads the content sended by a client and stores it into a buffer
     * --- can read all sizes but uses two read operations
     * @brief reads the size of the data in a first read op and reads the actual data in a second op
     * @param buff buffer to store the given content in
     */
    virtual char* read(unsigned int size);

    virtual vector<char> readVector(unsigned int size);

    /**
     * Sends the content of a buffer to connected client
     * --- can send all sizes but uses two send operations
     * @brief writes the size of the transmitting data in a first op and writes the actual data in a second op
     * @param buff buffer with the content to send
     */
    virtual void write(const char* buffer);

    virtual void write(const vector<char>& buffer);

    /**
     * @brief Reads all bytes available at the socket
     * @return read bytes
     */
    virtual char* readAll();

    virtual vector<char> readAllVector();

    /**
     * @brief Returns the number of bytes available to read
     * @return number of bytes
     */
    int bytesAvailable();

protected:

    TCPSocket(int family, int socket_fd, sockaddr_in own_addr, bool bound, bool accepted);

    /**
     * Stores the address of a connected client
     * Only set if the socket is in "server mode" and a client is connected
     */
    sockaddr_in m_client_addr;

    bool m_connected = false;
    bool m_listening = false;
    bool m_accepted = false;

};

}

#endif //SOCKETWRAPPER_TCPSOCKET_HPP
