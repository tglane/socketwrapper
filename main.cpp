#include <iostream>
#include <string>
#include <string.h>
#include "BaseSocket.hpp"
#include "UDPSocket.hpp"
#include "TCPSocket.hpp"

using sock_u = std::shared_ptr<socketwrapper::UDPSocket>;
using sock_t = std::shared_ptr<socketwrapper::TCPSocket>;

/**
 * Mainfile to test the implementation of this socketwrapper
 * not used by the CMakeLists.txt - it only creates a sharad library with TCP and UDP Socket
 */
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
        socketwrapper::TCPSocket socket(AF_INET);
        socket.bind(4711);
        socket.listen(5);
        sock_t conn = socket.accept();

        char buff[100];
        conn->read(&buff);
        std::cout << buff << std::endl;
    }



    if(argc == 2 && strncmp(argv[1], "st", 2) == 0)
    {
        socketwrapper::TCPSocket socket(AF_INET);
        socket.connect(4711, INADDR_ANY);
        char buff[] = {'h', 'a', 'l', 'l', 'o'};
        socket.write(&buff);
    }

}
