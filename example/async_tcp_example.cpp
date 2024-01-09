#include "../include/socketwrapper/tcp.hpp"
#include "../include/socketwrapper/utility.hpp"
#include <cstring>
#include <iostream>
#include <thread>
#include <vector>

int main(int argc, char** argv)
{
    if(argc <= 1)
        return 0;

    if(strcmp(argv[1], "r") == 0)
    {
        std::cout << "--- Receiver ---\n";
        net::tcp_acceptor<net::ip_version::v4> acceptor_two{"0.0.0.0", 4556};

        net::tcp_acceptor<net::ip_version::v4> acceptor{"0.0.0.0", 4433};
        std::cout << "Waiting for accept\n";

        // Make sure to prevent calling the callback on a moved-from (invalid) socket if you use references to async
        // sockets
        std::vector<net::tcp_connection<net::ip_version::v4>> conns;
        conns.reserve(2);

        acceptor.async_accept(
            [&acceptor, &conns](net::tcp_connection<net::ip_version::v4>&& conn)
            {
                auto buffer_one = std::array<char, 1024>{};
                auto buffer_two = std::array<char, 1024>{};

                std::cout << "Accepted\n";

                conns.push_back(std::move(conn));
                auto& sock = conns.back();

                // sock.async_read(net::span{buffer},
                //     [&sock, &buffer](size_t br)
                //     {
                //         std::cout << "Received: " << br << " - " << std::string_view{buffer.data(), br} << '\n';

                //         sock.async_read(net::span{buffer},
                //             [&buffer](size_t br) {
                //                 std::cout << "Inner receive: " << br << " - " << std::string_view{buffer.data(), br}
                //                           << '\n';
                //             });
                //     });
                auto read_fut_one = sock.promised_read(net::span{buffer_one});

                acceptor.async_accept(
                    [&conns](net::tcp_connection<net::ip_version::v4>&& conn)
                    {
                        std::cout << "Accepted again\n";
                        std::array<char, 1024> buffer;
                        conns.push_back(std::move(conn));
                        auto& sock = conns.back();

                        size_t br = sock.read(net::span(buffer), std::chrono::milliseconds(2000));
                        std::cout << "Received from second accept-read: " << br << "bytes -- "
                                  << std::string_view(buffer.data(), br) << '\n';
                        // sock.async_read(net::span{buffer},
                        //     [&buffer](size_t br) {
                        //         std::cout << "Received: " << br << " bytes from inner "
                        //                   << std::string_view{buffer.data(), br} << '\n';
                        //     });
                    });

                // Read data from buffer when read promise is resolved
                size_t bytes_read = read_fut_one.get();
                std::cout << "Promised read resolved! Read " << bytes_read << " bytes from future one. -- "
                          << std::string_view{buffer_one.data(), bytes_read} << '\n';

                sock.async_read(net::span{buffer_two},
                    [&buffer_two](size_t br) {
                        std::cout << "Received in callback: " << br << " - " << std::string_view{buffer_two.data(), br}
                                  << '\n';
                    });

                // auto read_fut_two = sock.promised_read(net::span{buffer_two});
                // bytes_read = read_fut_two.get();
                // std::cout << "Promised read resolved! Read " << bytes_read << " bytes from future two. -- "
                //           << std::string_view{buffer_two.data(), bytes_read} << '\n';
            });

        std::cout << "Wait for handlers to finish ...\n";
        net::async_run();
    }
    else if(strcmp(argv[1], "s") == 0)
    {
        {
            std::cout << "--- Sender ---\n";
            net::tcp_connection<net::ip_version::v4> sock{"127.0.0.1", 4433};
            std::cout << "Connected\n";
            std::vector<char> vec{'H', 'e', 'l', 'l', 'o'};

            std::this_thread::sleep_for(std::chrono::milliseconds(2000));
            std::string_view buffer{"Hello String_view-World"};
            sock.send(net::span{buffer.begin(), buffer.end()});
            std::cout << "Sent\n";

            std::this_thread::sleep_for(std::chrono::milliseconds(1000));
            sock.send(net::span{std::string_view{"Test, test, 123"}});
        }
        {
            std::cout << "--- Sender ---\n";
            net::tcp_connection<net::ip_version::v4> sock{"127.0.0.1", 4433};
            std::cout << "Connected again\n";
            std::vector<char> vec{'H', 'e', 'l', 'l', 'o'};
            // sock.send(net::span{vec});
            // sock.send(net::span {std::string {"Hello World"}});

            // std::this_thread::sleep_for(std::chrono::milliseconds(2000));
            std::string_view buffer{"Hello world from the second accepted connection!"};
            sock.async_send(net::span{buffer}, [](size_t) { std::cout << "Async message sent\n"; });
            // sock.promised_send(net::span{buffer}).get();

            net::async_run();
        }
    }
}
