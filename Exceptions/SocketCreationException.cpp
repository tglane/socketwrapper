//
// Created by timog on 22.12.18.
//

#include "../include/SocketCreationException.hpp"

namespace socketwrapper
{

const char* SocketCreationException::what()
{
    return "Error creation Socket";
}

}
