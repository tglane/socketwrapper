#include <iostream>
#include <string>
#include <string.h>
#include "BaseSocket.hpp"
#include "UDPSocket.hpp"

int main(int argc, char** argv)
{
    if(argc == 2 && strncmp(argv[1], "r", 1) == 0)
    {
        socketwrapper::UDPSocket receiver(AF_INET);
        receiver.bind(4711);

        char recv[100];
        receiver.recvfrom(recv);
        std::cout << recv << std::endl;

        receiver.recvfrom(recv);
        std::cout << recv << std::endl;

        receiver.close();
    }

    if(argc == 2 && strncmp(argv[1], "s", 1) == 0)
    {
        socketwrapper::UDPSocket sender(AF_INET);

        char s[] = {'h', 'a', 'l', 'l', 'o'};

        sender.sendto(s, sizeof(s), 4711, INADDR_ANY);

        sender.sendto(s, sizeof(s), 4711, INADDR_ANY);

        sender.close();
    }
}
