#include <iostream>
#include "BaseSocket.hpp"

int main(int argc, char** argv)
{
    socketwrapper::BaseSocket b(AF_INET, SOCK_STREAM);

    b.bind(4711);
}
