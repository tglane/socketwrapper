//
// Created by timog on 23.12.18.
//

#include "SocketBindException.hpp"

namespace socketwrapper
{

const char* SocketBindException::what()
{
    return "Error binding socket";
}

}
