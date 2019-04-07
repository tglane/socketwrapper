//
// Created by timog on 22.12.18.
//

#ifndef SOCKETWRAPPER_SOCKETCREATIONEXCEPTION_HPP
#define SOCKETWRAPPER_SOCKETCREATIONEXCEPTION_HPP

#include "BaseException.hpp"

namespace socketwrapper
{

/**
 * Simple Exception Class for errors while creationg a socket
 */
class SocketCreationException : public BaseException {

public:

    const char* what() { "Error creating socket"; }

};

}

#endif //SOCKETWRAPPER_SOCKETCREATIONEXCEPTION_HPP
