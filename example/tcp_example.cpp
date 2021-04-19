#include "../socketwrapper.hpp"
#include <iostream>
#include <thread>
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

        std::array<char, 1024> buffer;
        try {
            size_t bytes_read = sock.read(net::span {buffer});
            std::cout << "Received: " << bytes_read << '\n'
                << std::string_view {buffer.data(), bytes_read} << '\n';
        } catch(std::runtime_error&) {}

        auto sock2 = acceptor.accept();
        std::cout << "Accepted Again\n";
        size_t bytes_read = sock2.read(net::span {buffer}, std::chrono::milliseconds(3000));
        std::cout << "Received: " << bytes_read << '\n'
            << std::string_view {buffer.data(), bytes_read} << '\n';
    }
    else if(strcmp(argv[1], "s") == 0)
    {
        std::cout << "--- Sender ---\n";
        net::tcp_connection<net::ip_version::v4> sock {"127.0.0.1", 4433};
        std::cout << "Connected\n";
        std::vector<char> vec {'H', 'e', 'l', 'l', 'o'};
        // sock.send(net::span {vec});
        // sock.send(net::span {std::string {"Hello World"}});

        std::string_view buffer {"Hello String_view-World"};
        sock.send(net::span {buffer.begin(), buffer.end()});

        std::cout << "Sent\n";

        net::tcp_connection<net::ip_version::v4> sock2 {"127.0.0.1", 4433};
        std::this_thread::sleep_for(std::chrono::milliseconds(2000));
        sock2.send(net::span {std::string {"LulWWW"}});
        std::cout << "Sent again\n";
    }
}
