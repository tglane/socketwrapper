//
// Created by timog on 07.04.19.
//

#ifndef SOCKETWRAPPER_SETSOCKOPTEXCEPTION_HPP
#define SOCKETWRAPPER_SETSOCKOPTEXCEPTION_HPP

namespace socketwrapper
{

class SetSockOptException : public BaseException {

public:
    const char* what() { return "Error calling setsockopt"; }

};

}

#endif //SOCKETWRAPPER_SETSOCKOPTEXCEPTION_HPP
