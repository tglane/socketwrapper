//
// Created by timog on 23.12.18.
//

#ifndef SOCKETWRAPPER_UDPSOCKET_HPP
#define SOCKETWRAPPER_UDPSOCKET_HPP

#include "BaseSocket.hpp"

namespace socketwrapper
{

class UDPSocket : public BaseSocket
{
public:

    UDPSocket(int family);

    void recvfrom(void* buffer_to);

    void sendto(const void* buffer_from, size_t nbytes, int port, in_addr_t addr);

};

}

#endif //SOCKETWRAPPER_UDPSOCKET_HPP
