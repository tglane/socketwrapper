//
// Created by timog on 23.12.18.
//

#include "../include/SocketBoundException.hpp"

namespace socketwrapper
{

const char* SocketBoundException::what()
{
    return "Socket already bound";
}

}
