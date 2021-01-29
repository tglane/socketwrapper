//
// Created by timog on 22.12.18.
//

#ifndef SOCKETWRAPPER_BASEEXCEPTION_HPP
#define SOCKETWRAPPER_BASEEXCEPTION_HPP

#include <exception>

namespace socketwrapper {

/**
 * Abstract base exception class
 */
class BaseException : public std::exception {
public:
    virtual const char* what() = 0;
};

class SetSockOptException : public BaseException {
public:
    const char* what() override { return "Error calling setsockopt"; }
};

class SocketAcceptingException : public BaseException {
public:
    const char* what() override { return "Error accepting connection"; }
};

class SocketBindException : public BaseException {
public:
    const char* what() override { return "Error binding socket"; }
};

class SocketBoundException : BaseException {
public:
    const char *what() override { return "Socket already bound"; }
};

class SocketCloseException : BaseException
{
public:
    const char* what() override { return "Error closing socket"; }
};

class SocketConnectingException : public BaseException {
public:
    const char* what() override { return "Error connecting to the given address"; }
};

class SocketCreationException : public BaseException {
public:
    const char* what() override { return "Error creating socket"; }
};

class SocketListenException : public BaseException {
public:
    const char* what() override { return "Error setting Socket to listening mode"; }
};

class SocketReadException : public BaseException {
public:
    const char* what() override { return "Error reading data through the socket"; }
};

class SocketTimeoutException : public BaseException {
public:
    const char* what() override { return "Error timeout"; }
};

class SocketWriteException : public BaseException {
public:
    const char* what() override { return "Error transmitting data through the socket"; }
};

class ReadBytesAvailableException : BaseException {
public:
    const char* what() override { return "Error reading available bytes"; }
};

class SSLContextCreationException : BaseException {
public:
    const char* what() override { return "Error creating the ssl context"; }
};

}

#endif //SOCKETWRAPPER_BASEEXCEPTION_HPP

