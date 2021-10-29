#include "../include/socketwrapper/tcp.hpp"

#include <cstring>
#include <iostream>
#include <thread>

int main(int argc, char** argv)
{
    if(argc <= 1)
        return 0;

    if(strcmp(argv[1], "r") == 0)
    {
        std::cout << "--- Receiver ---\n";

        std::array<char, 10000> buffer;
        net::tcp_acceptor<net::ip_version::v4> acceptor {net::endpoint_v4 {"0.0.0.0", 4433}};

        std::cout << "Waiting for accept\n";
        auto opt = acceptor.accept(std::chrono::milliseconds(5000));
        if(!opt)
        {
            std::cout << "No acception\n";
            return 0;
        }
        const auto& sock = opt.value();
        std::cout << "Accepted\n";

        std::cout << "Wait for data ...\n";
        size_t bytes_read = sock.read(net::span {buffer});
        std::cout << "Received: " << bytes_read << " - " << std::string_view {buffer.data(), bytes_read} << '\n';

        bytes_read = sock.read(net::span {buffer}, std::chrono::milliseconds(4000));
        std::cout << "Received: " << bytes_read << " - " << std::string_view {buffer.data(), bytes_read} << '\n';
    }
    else if(strcmp(argv[1], "s") == 0)
    {
        std::cout << "--- Sender ---\n";
        net::tcp_connection<net::ip_version::v4> sock;
        std::cout << "Socket created\n";
        std::this_thread::sleep_for(std::chrono::milliseconds(1000));
        sock.connect(net::endpoint_v4 {"127.0.0.1", 4433, net::socket_type::stream});
        std::cout << "Connected\n";
        std::vector<char> vec {'H', 'e', 'l', 'l', 'o'};
        // sock.send(net::span {vec});
        // sock.send(net::span {std::string {"Hello World"}});

        std::this_thread::sleep_for(std::chrono::milliseconds(3000));
        sock.send(net::span {vec.begin(), vec.end()});

        std::cout << "Sent\n";
        std::this_thread::sleep_for(std::chrono::milliseconds(1000));
        std::string_view buffer {"Hello String_view-World"};
        sock.send(net::span {buffer.begin(), buffer.end()});
        std::cout << "Sent again\n";
        return 0;
    }
}
