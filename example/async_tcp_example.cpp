#include "../include/socketwrapper/tcp.hpp"
#include <cstring>
#include <iostream>
#include <thread>
#include <vector>

extern "C" {
    int pid_shutdown_sockets(int, int);
}

int main(int argc, char** argv)
{
    if (argc <= 1)
        return 0;

    if (strcmp(argv[1], "r") == 0)
    {
        std::cout << "--- Receiver ---\n";
        auto acceptor = net::tcp_acceptor<net::ip_version::v4>(net::endpoint_v4("0.0.0.0", 4433));
        auto acceptor_two = net::tcp_acceptor<net::ip_version::v4>(net::endpoint_v4("0.0.0.0", 4556));

        std::cout << "Waiting for accept\n";

        // Make sure to prevent calling the callback on a moved-from (invalid) socket if you use references to async
        // sockets
        auto conns = std::vector<net::tcp_connection<net::ip_version::v4>>();
        conns.reserve(2);

        acceptor.async_accept(
            [&acceptor, &conns](net::tcp_connection<net::ip_version::v4>&& conn, std::exception_ptr ex)
            {
                auto buffer_one = std::array<char, 1024>{};
                auto buffer_two = std::array<char, 1024>{};

                std::cout << "Accepted\n";
                if (ex != nullptr)
                {
                    std::cout << "But with error so not really accepted :(\n";
                    return;
                }

                conns.push_back(std::move(conn));
                auto& sock = conns.back();

                auto read_fut_one = sock.promised_read(net::span{buffer_one});

                acceptor.async_accept(
                    [&conns](net::tcp_connection<net::ip_version::v4>&& conn, std::exception_ptr)
                    {
                        std::cout << "Accepted again\n";
                        std::array<char, 1024> buffer;
                        conns.push_back(std::move(conn));
                        auto& sock = conns.back();

                        const auto read_result = sock.read(net::span(buffer), std::chrono::milliseconds(2000));
                        if (read_result.has_value())
                        {
                            std::cout << "Received from second accept-read: " << *read_result << "bytes -- "
                                      << std::string_view(buffer.data(), *read_result) << '\n';
                        }
                        auto result = sock.promised_read(net::span(buffer));
                        auto br = result.get();
                        std::cout << "Received from second accept-read: " << br << "bytes -- "
                                  << std::string_view(buffer.data(), br) << '\n';

                        // sock.async_read(net::span{buffer},
                        //     [&buffer](size_t br, std::exception_ptr) {
                        //         std::cout << "Nested received: " << br << " bytes from inner "
                        //                   << std::string_view{buffer.data(), br} << '\n';
                        //     });
                    });

                // Read data from buffer when read promise is resolved
                size_t bytes_read = read_fut_one.get();
                std::cout << "Promised read resolved! Read " << bytes_read << " bytes from future one. -- "
                          << std::string_view{buffer_one.data(), bytes_read} << '\n';

                sock.async_read(net::span{buffer_two},
                    [&buffer_two](size_t br, std::exception_ptr) {
                        std::cout << "Received in callback: " << br << " - " << std::string_view{buffer_two.data(), br}
                                  << '\n';
                    });
            });

        std::cout << "Wait for handlers to finish ...\n";
        net::async_run();
    }
    else if (strcmp(argv[1], "s") == 0)
    {
        std::cout << "--- Sender ---\n";
        {
            auto sock = net::tcp_connection<net::ip_version::v4>(net::endpoint_v4("127.0.0.1", 4433));
            std::cout << "Connected\n";
            auto vec = std::vector<char>{'H', 'e', 'l', 'l', 'o'};

            std::this_thread::sleep_for(std::chrono::milliseconds(2000));
            std::string_view buffer{"Hello String_view-World"};
            sock.send(net::span{buffer.begin(), buffer.end()});
            std::cout << "Sent first connection first message\n";

            std::this_thread::sleep_for(std::chrono::milliseconds(1000));
            sock.send(net::span{std::string_view{"Test, test, 123"}});
            std::cout << "Sent first connection second message\n";
        }
        {
            auto sock = net::tcp_connection<net::ip_version::v4>(net::endpoint_v4("127.0.0.1", 4433));
            std::cout << "Connected again\n";
            std::vector<char> vec{'H', 'e', 'l', 'l', 'o'};

            auto send_fut = sock.promised_send(net::span{"Promised to say hello"});
            send_fut.wait();
            std::cout << "Sent second connection first message\n";

            std::this_thread::sleep_for(std::chrono::milliseconds(1000));

            // std::this_thread::sleep_for(std::chrono::milliseconds(2000));
            std::string_view buffer{"Hello world from the second accepted connection!"};
            // sock.async_send(net::span{buffer}, [](size_t, std::exception_ptr) { std::cout << "Async message sent\n";
            // });
            sock.send(net::span{buffer});
            // sock.promised_send(net::span{buffer}).get();
            std::cout << "Sent second connection second message\n";

            net::async_run();
        }
    }
}
