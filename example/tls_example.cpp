#include "../include/socketwrapper/tls.hpp"
#include <cstring>
#include <iostream>
#include <thread>

using namespace std::literals::chrono_literals;

int main(int argc, char** argv)
{
    if (argc <= 1)
        return 0;

    if (strcmp(argv[1], "r") == 0)
    {
        std::cout << "--- Receiver ---\n";

        auto acceptor = net::tls_acceptor_v4("./cert.pem", "./key.pem", net::endpoint_v4("0.0.0.0", 4433));
        std::cout << "Waiting for accept for 4 seconds...\n";
        auto sock = acceptor.accept(4000ms);
        if (!sock)
        {
            std::cout << "No connection available\n";
            return 0;
        }
        std::cout << "Accepted\n";

        auto buffer = std::array<char, 1024>{};
        const auto read_result = sock->read(net::span{buffer.begin(), buffer.end()}, 2000ms);
        if (read_result.has_value())
        {
            std::cout << "Received: " << *read_result << '\n' << std::string_view{buffer.data(), *read_result} << '\n';
        }
    }
    else if (strcmp(argv[1], "s") == 0)
    {
        std::cout << "--- Sender ---\n";
        auto sock = net::tls_connection_v4("./cert.pem", "./key.pem", net::endpoint_v4("127.0.0.1", 4433));
        std::cout << "Connected\n";
        sock.send(net::span{std::string{"Hello World"}});
        std::cout << "Sent" << '\n';
    }
}
