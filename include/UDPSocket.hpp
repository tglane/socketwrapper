//
// Created by timog on 23.12.18.
//

#ifndef SOCKETWRAPPER_UDPSOCKET_HPP
#define SOCKETWRAPPER_UDPSOCKET_HPP

#include "BaseSocket.hpp"

namespace socketwrapper
{

/**
 * Simple udp socket class wrapping the c sockets into a c++ class
 * Only for udp sockets
 */
class UDPSocket : public BaseSocket
{
public:

    using Ptr = std::shared_ptr<UDPSocket>;

    /**
     * Constructor
     * @param family
     */
    UDPSocket(int family);

    /**
     * Reads the content sended by a client using the underlying socket
     * @param buffer_to write the received data
     */
    std::unique_ptr<char[]> receive_from(int bufflen);

    vector<char> receive_vector(int bufflen);

    /**
     * Sends the data from a buffer a client using the underlying socket
     * @param buffer_from buffer with data to send
     * @param port of the client
     * @param addr of the client
     */
    void send_to(const char* buffer_from, int port, in_addr_t addr);

    void send_to(const char* buffer_from, int port, const string& addr);

    void send_to(const vector<char>& buffer_from, int port, const string& addr);

};

}

#endif //SOCKETWRAPPER_UDPSOCKET_HPP
