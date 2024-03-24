#include "../include/socketwrapper/udp.hpp"
#include <cstring>
#include <iostream>
#include <string>
#include <thread>

int main(int argc, char** argv)
{
    if (argc <= 1)
        return 0;

    if (strcmp(argv[1], "r") == 0)
    {
        std::cout << "--- Receiver ---\n";
        auto sock = net::udp_socket<net::ip_version::v4>(net::endpoint_v4("0.0.0.0", 4433));

        auto buffer = std::array<char, 1024>{};

        // Test the read timeout
        std::cout << "Started receiving\n";
        const auto result = sock.read(net::span{buffer}, std::chrono::milliseconds(10000));
        if (result.has_value())
        {
            const auto& [br, from] = result.value();
            std::cout << "Received within timeframe: " << std::string_view{buffer.data(), br} << '\n';
        }
        else
        {
            std::cout << "Received no data in the specified timeframe\n";
        }

        sock.async_read(net::span{buffer},
            [&sock, &buffer](std::pair<size_t, net::endpoint_v4> result, std::exception_ptr)
            {
                std::cout << "1. Received " << result.first << " bytes. -- "
                          << std::string_view{buffer.data(), result.first} << '\n';

                sock.async_read(net::span{buffer},
                    [&sock, &buffer](std::pair<size_t, net::endpoint_v4> result, std::exception_ptr)
                    {
                        std::cout << "2. Received " << result.first << " bytes. -- "
                                  << std::string_view{buffer.data(), result.first} << '\n';

                        sock.async_read(net::span{buffer},
                            [&sock, &buffer](std::pair<size_t, net::endpoint_v4> result, std::exception_ptr)
                            {
                                std::cout << "Inner received " << result.first << " bytes. -- "
                                          << std::string_view{buffer.data(), result.first} << '\n';

                                auto read_fut = sock.promised_read(net::span{buffer});
                                auto read_res = read_fut.get();
                                std::cout << "Promised inner read: " << std::string_view(buffer.data(), read_res.first)
                                          << '\n';

                                sock.async_read(net::span{buffer},
                                    [&buffer](std::pair<size_t, net::endpoint_v4> result, std::exception_ptr)
                                    {
                                        std::cout << "Nested inner received " << result.first << " bytes. -- "
                                                  << std::string_view{buffer.data(), result.first} << '\n';
                                    });
                            });
                    });
            });

        std::cout << "Waiting ...\n";
        net::async_run();
        std::cout << "All async events handled\n";
    }
    else if (strcmp(argv[1], "s") == 0)
    {
        auto io_loop = std::thread([]() { net::async_run(); });

        int port = (argc > 2) ? std::stoi(argv[2]) : 4433;
        std::cout << "Port: " << port << '\n';

        std::cout << "--- Sender ---\n";
        auto sock = net::udp_socket<net::ip_version::v4>();

        auto str = std::string("Hello async UDP world!");
        // sock.send(net::endpoint_v4("127.0.0.1", port), net::span{str});
        auto first_send = sock.promised_send(net::endpoint_v4("127.0.0.1", port), net::span{str});
        first_send.wait();
        std::cout << "First message send\n";

        sock.send(net::endpoint_v4("127.0.0.1", port), net::span{"KekW"});
        std::cout << "Second message send\n";

        std::this_thread::sleep_for(std::chrono::milliseconds(2000));

        sock.send(net::endpoint_v4("127.0.0.1", port), net::span{"Third message"});
        std::cout << "Last message sent!\n";

        // net::async_run();
        io_loop.join();
    }
}
