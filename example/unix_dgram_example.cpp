#include "../include/socketwrapper/unixdgram.hpp"
#include <cstring>
#include <iostream>
#include <thread>

int main(int argc, char** argv)
{
    if (argc <= 1)
        return 0;

    if (strcmp(argv[1], "r") == 0)
    {
        std::cout << "--- Receiver ---\n";

        auto sock = net::unix_dgram_socket(net::endpoint_unix("/tmp/sock2"));

        auto buffer = std::array<char, 1024>{};
        const auto [bytes_read, peer] = sock.read(net::span(buffer));
        std::cout << "Peer addr: " << peer.get_addr_string()
                  << "; Bytes read: " << bytes_read << '\n';
        std::cout << std::string_view(buffer.data(), bytes_read) << '\n';

        const auto read_result = sock.read(net::span{buffer}, std::chrono::milliseconds(4000));
        if (read_result.has_value())
        {
            const auto& [bytes_read, peer_opt] = read_result.value();
            std::cout << "Peer addr: " << peer_opt.get_addr_string()
                      << "; Bytes read: " << bytes_read << '\n';
            std::cout << std::string_view{buffer.data(), bytes_read} << '\n';
        }
        else
        {
            std::cout << "No message received :(\n";
        }
    }
    else if (strcmp(argv[1], "s") == 0)
    {
        std::cout << "--- Sender ---\n";

        auto sock = net::unix_dgram_socket();

        auto buffer = std::string{"Hello world"};
        const auto endpoint = net::endpoint_unix("/tmp/sock2");
        sock.send(endpoint, net::span(buffer));
        std::cout << "All messages sent." << std::endl;

        std::this_thread::sleep_for(std::chrono::milliseconds(2000));

        auto vec = std::vector<char>{'A', 'B', 'C'};
        sock.send(endpoint, net::span(vec));
        sock.send(endpoint, net::span("KekWWW"));
        std::cout << "All messages sent. Again." << std::endl;
    }
}
