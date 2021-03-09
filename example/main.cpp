#define TLS_ENABLED

#include "../socketwrapper.hpp"
#include <iostream>
#include <cstring>

int main(int argc, char** argv)
{
    if(argc <= 1)
        return 0;

    if(strcmp(argv[1], "r") == 0)
    {
        std::cout << "--- Receiver ---\n";

        // net::udp_socket<net::ip_version::v4> sock {"0.0.0.0", 4433};
        // auto buffer = sock.read<char>(512);
        // std::cout << std::string_view {buffer.data(), buffer.size() } << '\n';

        // net::tcp_acceptor<net::ip_version::v4> acceptor {"0.0.0.0", 4433};
        net::tls_acceptor<net::ip_version::v4> acceptor {"./cert.pem", "./key.pem", "0.0.0.0", 4433};
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
        // net::udp_socket<net::ip_version::v4> sock {};
        // // std::vector<char> buffer {'h', 'a', 'l', 'l', 'o'};
        // std::string_view buffer {"Hello world lololo"};
        // sock.send("127.0.0.1", 4433, buffer);

        // net::tcp_connection<net::ip_version::v4> sock {"127.0.0.1", 4433};
        net::tls_connection<net::ip_version::v4> sock {"./cert.pem", "./key.pem", "127.0.0.1", 4433};
        std::cout << "Connected\n";
        sock.send("Hello World");
        sock.send("Hello the second");
        std::cout << "Sent" << std::endl;
    }
}

