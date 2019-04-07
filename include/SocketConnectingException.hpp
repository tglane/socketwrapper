//
// Created by timog on 07.04.19.
//

#ifndef SOCKETWRAPPER_SOCKETCONNECTINGEXCEPTION_HPP
#define SOCKETWRAPPER_SOCKETCONNECTINGEXCEPTION_HPP

namespace socketwrapper
{

class SocketConnectingException : public BaseException {

public:
    const char* what() { return "Error connecting to the given address"; }

};

}

#endif //SOCKETWRAPPER_SOCKETCONNECTINGEXCEPTION_HPP
