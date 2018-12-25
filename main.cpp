#include <iostream>
#include <string>
#include <string.h>
#include "BaseSocket.hpp"
#include "UDPSocket.hpp"
#include "TCPSocket.hpp"

int main(int argc, char** argv)
{
    if(argc == 2 && strncmp(argv[1], "ru", 2) == 0)
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

    if(argc == 2 && strncmp(argv[1], "su", 2) == 0)
    {
        socketwrapper::UDPSocket sender(AF_INET);

        char s[] = {'h', 'a', 'l', 'l', 'o'};

        sender.sendto(s, sizeof(s), 4711, INADDR_ANY);

        sender.sendto(s, sizeof(s), 4711, INADDR_ANY);

        sender.close();
    }

    if(argc == 2 && strncmp(argv[1], "rt", 2) == 0)
    {
        socketwrapper::TCPSocket receiver(AF_INET);

        receiver.bind(4711);
        std::cout << "n b" << std::endl;
        receiver.listen();
        std::cout << "n l" << std::endl;
        receiver.accept();
        std::cout << "n a" << std::endl;

        char r[100];
        std::cout << "moin" << std::endl;
        receiver.read(r, sizeof(r));

        std::cout << r << std::endl;

        receiver.close();
    }



    if(argc == 2 && strncmp(argv[1], "st", 2) == 0)
    {
        socketwrapper::TCPSocket sender(AF_INET);

        sender.connect(4711, INADDR_ANY);

        char s[] = {'h', 'a', 'l', 'l', 'o'};
        sender.write(s, sizeof(s));

        sender.close();
    }
}
