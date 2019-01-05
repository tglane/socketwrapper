#include <iostream>
#include <string>
#include <string.h>
#include "BaseSocket.hpp"
#include "UDPSocket.hpp"
#include "TCPSocket.hpp"

using sock_u = std::shared_ptr<socketwrapper::UDPSocket>;
using sock_t = std::shared_ptr<socketwrapper::TCPSocket>;

int main(int argc, char** argv)
{
    if(argc == 2 && strncmp(argv[1], "ru", 2) == 0)
    {
        sock_u receiver(new socketwrapper::UDPSocket(AF_INET));
        receiver->bind(4711);

        char recv[100];
        receiver->recvfrom(recv);
        std::cout << recv << std::endl;

        receiver->close();
    }

    if(argc == 2 && strncmp(argv[1], "su", 2) == 0)
    {
        sock_u sender(new socketwrapper::UDPSocket(AF_INET));

        char s[] = {'h', 'a', 'l', 'l', 'o'};

        sender->sendto(s, sizeof(s), 4711, INADDR_ANY);

        sender->close();
    }

    if(argc == 2 && strncmp(argv[1], "rt", 2) == 0)
    {
        socketwrapper::TCPSocket serviceSocket(AF_INET);

        serviceSocket.bind(4711);
        serviceSocket.listen();
        serviceSocket.accept();

        char recv[100];
        serviceSocket.read(recv, sizeof(recv));
        std::cout << recv << std::endl;


        serviceSocket.read(recv, sizeof(recv));
        std::cout << recv << std::endl;

        serviceSocket.close();
    }



    if(argc == 2 && strncmp(argv[1], "st", 2) == 0)
    {
        socketwrapper::TCPSocket sender(AF_INET);

        sender.connect(4711, INADDR_ANY);

        char s[] = {'h', 'a', 'l', 'l', 'o'};
        sender.write(s, sizeof(s));

        sender.write(s, sizeof(s));

        sender.close();
    }
}
