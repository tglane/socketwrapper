//
// Created by timog on 23.12.18.
//

#ifndef SOCKETWRAPPER_SOCKETBINDEXCEPTION_HPP
#define SOCKETWRAPPER_SOCKETBINDEXCEPTION_HPP

#include "BaseException.hpp"

namespace socketwrapper {

class SocketBindException : public BaseException {

public:

    const char* what() override { return "Error binding socket"; }

};

}

#endif //SOCKETWRAPPER_SOCKETBINDEXCEPTION_HPP
