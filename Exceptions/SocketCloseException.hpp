//
// Created by timog on 22.12.18.
//

#ifndef SOCKETWRAPPER_SOCKETCLOSEEXCEPTION_HPP
#define SOCKETWRAPPER_SOCKETCLOSEEXCEPTION_HPP

#include "BaseException.hpp"

namespace socketwrapper
{

/**
 * Simple Exception class for errors while closing a socket
 */
class SocketCloseException : BaseException
{

public:

    const char* what();

};

}

#endif //SOCKETWRAPPER_SOCKETCLOSEEXCEPTION_HPP
