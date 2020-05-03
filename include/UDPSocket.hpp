//
// Created by timog on 23.12.18.
//

#ifndef SOCKETWRAPPER_UDPSOCKET_HPP
#define SOCKETWRAPPER_UDPSOCKET_HPP

#include "BaseSocket.hpp"

namespace socketwrapper
{

/**
 * @brief Simple udp socket class wrapping the c sockets into a c++ class
 * Only for udp sockets
 */
class UDPSocket : public BaseSocket
{

public:

    /**
     * Constructor
     * @param int family
     */
    explicit UDPSocket(int family);

    UDPSocket(UDPSocket&& other);

    UDPSocket& operator=(UDPSocket&& other);

    /**
     * @brief Reads the content sended by a client using the underlying socket and returns a buffer containing
     *  the received message
     * @param int max number of bytes to read
     * @throws SocketReadException
     */
    std::unique_ptr<char[]> receive_from(size_t size) const;

    std::vector<char> receive_vector(size_t size) const;

    /**
     * Sends the data from a buffer a client using the underlying socket
     * @param buffer_from buffer with data to send
     * @param int port of the client
     * @param addr of the client
     * @throws SocketWriteException
     */
    void send_to(const char* buffer_from, int port, in_addr_t addr) const;

    void send_to(const char* buffer_from, int port, std::string_view addr) const;

    void send_to(const std::vector<char>& buffer_from, int port, std::string_view addr) const;

private:

    /**
     * @brief Read data from an underlying raw socket
     * @param buffer to read into
     * @param size of the data to read from socket
     */
    int read_raw(char* const buffer, size_t size, sockaddr_in& from) const;

};

}

#endif //SOCKETWRAPPER_UDPSOCKET_HPP

