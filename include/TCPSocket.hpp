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
 * @brief Simple tcp socket class wrapping the c socket to a c++ class
 * Only for tcp sockets
 */
class TCPSocket : public BaseSocket
{

public:

    explicit TCPSocket(int family);

    /**
     * @brief Sets the internal socket in listening mode
     * @param int queuesize max number of clients waiting for establishing a connection
     * @throws SocketListenException
     */
    void listen(int queuesize = 5);

    /**
     * @brief Establishes a connection to a server
     * @param int port_to port of the server to connect to
     * @param int addr_to ip address of the server to connect to
     * @throws SocketConnectingException
     */
    virtual void connect(int port_to, in_addr_t addr_to);

    virtual void connect(int port_to, const string& addr_to);

    /**
     * @briefWaits for a client to connect to the socket
     *  Usable only after call of listen() and m_listeing and m_bound true
     * @return std::unique_ptr<TCPSocket> to handle the established connection
     * @throws SocketAcceptingException
     */
    std::unique_ptr<TCPSocket> accept();

    /**
     * @brief Reads the content sended by a client and stores it into a buffer
     * @param buff buffer to store the given content in
     * @throws SocketReadException
     */
    virtual std::unique_ptr<char[]> read(unsigned int size);

    virtual vector<char> read_vector(unsigned int size);

    /**
     * @brief Sends the content of a buffer to connected client
     * @param buff buffer with the content to send
     * @throws SocketWriteException
     */
    virtual void write(const char* buffer);

    virtual void write(const vector<char>& buffer);

    /**
     * @brief Reads all bytes available at the socket
     * @return buffer containing all read bytes
     * @throws SocketReadException
     */
    virtual std::unique_ptr<char[]> read_all();

    virtual vector<char> read_all_vector();

    /**
     * @brief Returns the number of bytes available to read
     * @return int
     * @throws ReadBytesAvailableException
     */
    int bytes_available();

    /**
     * @brief Closes the internal socket filedescriptor m_sockfd and resets the state
     * @throws SocketCloseException
     */
    void close() override ;

protected:

    TCPSocket(int family, int socket_fd, sockaddr_in own_addr, int state, int tcp_state);

    /**
     * Stores the address of a connected client
     * Only set if the socket is in "server mode" and a client is connected
     */
    sockaddr_in m_client_addr;

    int m_tcp_state;
    enum tcp_state {WAITING, CONNECTED, LISTENING, ACCEPTED};

};

}

#endif //SOCKETWRAPPER_TCPSOCKET_HPP
