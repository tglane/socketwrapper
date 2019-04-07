//
// Created by timog on 23.12.18.
//

#ifndef SOCKETWRAPPER_SOCKETBOUNDEXCEPTION_HPP
#define SOCKETWRAPPER_SOCKETBOUNDEXCEPTION_HPP

#include "BaseException.hpp"

namespace socketwrapper {

class SocketBoundException : BaseException {

public:

    const char *what() { return "Socket already bound"; }

};

}

#endif //SOCKETWRAPPER_SOCKETBOUNDEXCEPTION_HPP
