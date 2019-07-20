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

    /**
     * @brief Reads the content sended by a client using the underlying socket and returns a buffer containing
     *  the received message
     * @param int max number of bytes to read
     * @throws SocketReadException
     */
    std::unique_ptr<char[]> receive_from(int bufflen);

    vector<char> receive_vector(int bufflen);

    /**
     * Sends the data from a buffer a client using the underlying socket
     * @param buffer_from buffer with data to send
     * @param int port of the client
     * @param addr of the client
     * @throws SocketWriteException
     */
    void send_to(const char* buffer_from, int port, in_addr_t addr);

    void send_to(const char* buffer_from, int port, const string& addr);

    void send_to(const vector<char>& buffer_from, int port, const string& addr);

};

}

#endif //SOCKETWRAPPER_UDPSOCKET_HPP
