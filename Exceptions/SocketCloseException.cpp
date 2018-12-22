//
// Created by timog on 22.12.18.
//

#include "SocketCloseException.hpp"

namespace socketwrapper
{

const char* SocketCloseException::what()
{
    return "Error closing socket";
}

}