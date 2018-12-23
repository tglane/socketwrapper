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

    void recvfrom(void* buffer_to, size_t nbytes);

    void sendto(const void* buffer_from, size_t nbytes);

};

}

#endif //SOCKETWRAPPER_UDPSOCKET_HPP
