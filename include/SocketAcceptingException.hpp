//
// Created by timog on 07.04.19.
//

#ifndef SOCKETWRAPPER_SOCKETACCEPTINGEXCEPTION_HPP
#define SOCKETWRAPPER_SOCKETACCEPTINGEXCEPTION_HPP

namespace socketwrapper
{

class SocketAcceptingException : public BaseException {

public:
    const char* what() { return "Error accepting connection"; }

};

}

#endif //SOCKETWRAPPER_SOCKETACCEPTINGEXCEPTION_HPP
