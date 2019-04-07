//
// Created by timog on 07.04.19.
//

#ifndef SOCKETWRAPPER_SOCKETWRITEEXCEPTION_HPP
#define SOCKETWRAPPER_SOCKETWRITEEXCEPTION_HPP

namespace socketwrapper
{

class SocketWriteException : public BaseException {

public:
    const char* what() { return "Error transmitting data through the socket"; }

};

}

#endif //SOCKETWRAPPER_SOCKETWRITEEXCEPTION_HPP
