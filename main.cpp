#include <iostream>
#include <string>
#include <string.h>
#include "include/BaseSocket.hpp"
#include "include/UDPSocket.hpp"
#include "include/TCPSocket.hpp"

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

        char* recv = receiver->recvfrom(1024);
        std::string s(recv);
        std::cout << s << std::endl;

        receiver->close();
    }

    if(argc == 2 && strncmp(argv[1], "su", 2) == 0)
    {
        sock_u sender(new socketwrapper::UDPSocket(AF_INET));

        //char s[] = {'h', 'a', 'l', 'l', 'o'};
        char s[] = "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=UTF-8\r\n\r\n<!DOCTYPE html><html><head><title>Bye-bye baby bye-bye</title><body><h1>Goodbye, world!</h1></body></html>\r\n";
        //char s[] = "HAllo wie geht es dir du arschgeige?";

        sender->sendto(s, 4711, INADDR_ANY);
        sender->close();
    }

    if(argc == 2 && strncmp(argv[1], "rt", 2) == 0)
    {
        socketwrapper::TCPSocket socket(AF_INET);
        socket.bind(4711);
        socket.listen(5);
        socketwrapper::TCPSocket::Ptr conn = socket.accept();

        char* buff = conn->read();
        std::string s(buff);
        std::cout << s << std::endl;
        conn->write("ok");
        conn->close();
        socket.close();
    }



    if(argc == 2 && strncmp(argv[1], "st", 2) == 0)
    {
        socketwrapper::TCPSocket socket(AF_INET);
        socket.connect(4711, INADDR_ANY);
        char buff[] = "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=UTF-8\r\n\r\n<!DOCTYPE html><html><head><title>Bye-bye baby bye-bye</title><body><h1>Goodbye, world!</h1></body></html>\r\n";
        socket.write(buff);

	    char* buffer = socket.read();
        std::string s(buffer);
        std::cout << s << std::endl;
        socket.close();
    }

}
