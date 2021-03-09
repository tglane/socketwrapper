#include "../socketwrapper.hpp"
#include <iostream>
#include <cstring>

int main(int argc, char**argv)
{
    if(argc <= 1)
        return 0;

    if(strcmp(argv[1], "r") == 0)
    {
        std::cout << "--- Receiver ---\n";

        net::tcp_acceptor<net::ip_version::v4> acceptor {"0.0.0.0", 4433};
        std::cout << "Waiting for accept\n";
        auto sock = acceptor.accept();
        std::cout << "Accepted\n";

        while(true)
        {
            std::vector<char> buffer = sock.read<char>(1024);
            if(buffer.size() == 0)
                break;
            std::cout << "Received: " << buffer.size() << '\n'
                << std::string_view {buffer.data(), buffer.size()} << std::endl;
        }
    }
    else if(strcmp(argv[1], "s") == 0)
    {
        std::cout << "--- Sender ---\n";
        net::tcp_connection<net::ip_version::v4> sock {"127.0.0.1", 4433};
        std::cout << "Connected\n";
        sock.send("Hello World");
        sock.send("Hello the second");
        std::cout << "Sent" << std::endl;
    }
}

