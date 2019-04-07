//
// Created by timog on 07.04.19.
//

#ifndef SOCKETWRAPPER_SOCKETREADEXCEPTION_HPP
#define SOCKETWRAPPER_SOCKETREADEXCEPTION_HPP

namespace socketwrapper
{

class SocketReadException : public BaseException {

public:
    const char* what() { return "Error reading data through the socket"; }

};

}

#endif //SOCKETWRAPPER_SOCKETREADEXCEPTION_HPP
