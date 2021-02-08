//
// Created by timog on 22.12.18.
//

#ifndef SOCKETWRAPPER_BASEEXCEPTION_HPP
#define SOCKETWRAPPER_BASEEXCEPTION_HPP

#include <exception>

namespace socketwrapper {

class SetSockOptException : public std::exception {
public:
    const char* what() const throw () { return "Error calling setsockopt"; }
};

class SocketAcceptingException : public std::exception {
public:
    const char* what() const throw () { return "Error accepting connection"; }
};

class SocketBindException : public std::exception {
public:
    const char* what() const throw () { return "Error binding socket"; }
};

class SocketBoundException : std::exception {
public:
    const char *what() const throw () { return "Socket already bound"; }
};

class SocketCloseException : std::exception {
public:
    const char* what() const throw () { return "Error closing socket"; }
};

class SocketConnectingException : public std::exception {
public:
    const char* what() const throw () { return "Error connecting to the given address"; }
};

class SocketCreationException : public std::exception {
public:
    const char* what() const throw () { return "Error creating socket"; }
};

class SocketListenException : public std::exception {
public:
    const char* what() const throw () { return "Error setting Socket to listening mode"; }
};

class SocketReadException : public std::exception {
public:
    const char* what() const throw () { return "Error reading data through the socket"; }
};

class SocketTimeoutException : public std::exception {
public:
    const char* what() const throw () { return "Error timeout"; }
};

class SocketWriteException : public std::exception {
public:
    const char* what() const throw () { return "Error transmitting data through the socket"; }
};

class ReadBytesAvailableException : std::exception {
public:
    const char* what() const throw () { return "Error reading available bytes"; }
};

class SSLContextCreationException : std::exception {
public:
    const char* what() const throw () { return "Error creating the ssl context"; }
};

}

#endif //SOCKETWRAPPER_BASEEXCEPTION_HPP

