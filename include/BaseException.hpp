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

}

#endif //SOCKETWRAPPER_BASEEXCEPTION_HPP
