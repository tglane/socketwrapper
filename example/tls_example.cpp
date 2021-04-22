#define TLS_ENABLED

#include "../socketwrapper.hpp"
#include <iostream>
#include <thread>
#include <cstring>

using namespace std::literals::chrono_literals;

int main(int argc, char** argv)
{
    if(argc <= 1)
        return 0;

    if(strcmp(argv[1], "r") == 0)
    {
        std::cout << "--- Receiver ---\n";

        net::tls_acceptor<net::ip_version::v4> acceptor {"./cert.pem", "./key.pem", "0.0.0.0", 4433};
        std::cout << "Waiting for accept\n";
        auto sock = acceptor.accept(4000ms);
        if(!sock)
        {
            std::cout << "No connection available\n";
            return 0;
        }
        std::cout << "Accepted" << std::endl;

        std::array<char, 1024> buffer;
        size_t bytes_read = sock->read(net::span {buffer.begin(), buffer.end()});
        std::cout << "br: " << bytes_read << std::endl;
        std::cout << "Received: " << bytes_read << '\n'
            << std::string_view {buffer.data(), bytes_read} << std::endl;
    }
    else if(strcmp(argv[1], "s") == 0)
    {
        std::cout << "--- Sender ---\n";
        std::this_thread::sleep_for(2000ms);
        net::tls_connection<net::ip_version::v4> sock {"./cert.pem", "./key.pem", "127.0.0.1", 4433};
        std::cout << "Connected\n";
        sock.send(net::span {std::string {"Hello World"}});
        std::cout << "Sent" << std::endl;
    }
}
