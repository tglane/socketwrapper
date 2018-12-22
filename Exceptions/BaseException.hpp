//
// Created by timog on 22.12.18.
//

#ifndef SOCKETWRAPPER_BASEEXCEPTION_HPP
#define SOCKETWRAPPER_BASEEXCEPTION_HPP

namespace socketwrapper {

/**
 * Abstract base exception class
 */
class BaseException {

public:

    virtual const char* what() const throw() = 0;

};

}

#endif //SOCKETWRAPPER_BASEEXCEPTION_HPP
