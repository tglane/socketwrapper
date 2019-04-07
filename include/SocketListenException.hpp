//
// Created by timog on 07.04.19.
//

#ifndef SOCKETWRAPPER_SOCKETLISTENEXCEPTION_HPP
#define SOCKETWRAPPER_SOCKETLISTENEXCEPTION_HPP

namespace socketwrapper
{

class SocketListenException : public BaseException {

public:

    const char* what() { return "Error setting Socket to listening mode"; }

};

}

#endif //SOCKETWRAPPER_SOCKETLISTENEXCEPTION_HPP
