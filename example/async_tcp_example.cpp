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
        net::tcp_acceptor<net::ip_version::v4> acceptor_two {"0.0.0.0", 4556};
        // acceptor_two.async_accept([](net::tcp_connection<net::ip_version::v4>&& sock) {
        //     std::cout << sock.get() << std::endl;
        // });

        net::tcp_acceptor<net::ip_version::v4> acceptor {"0.0.0.0", 4433};
        std::cout << "Waiting for accept\n";
        std::vector<net::tcp_connection<net::ip_version::v4>> conns;
        acceptor.async_accept([&acceptor, &conns](net::tcp_connection<net::ip_version::v4>&& conn) {
            std::array<char, 1024> buffer;
            std::cout << "Accepted\n";

            conns.push_back(std::move(conn));
            auto& sock = conns.back();

            sock.async_read(net::span {buffer}, [&sock, &buffer](size_t br) {
                std::cout << "Received: " << br << " - " << std::string_view {buffer.data(), br} << '\n';

                sock.async_read(net::span {buffer}, [&buffer](size_t br) {
                    std::cout << "Inner receive: " << br << " - " << std::string_view {buffer.data(), br} << '\n';
                });
            });


            acceptor.async_accept([&conns](net::tcp_connection<net::ip_version::v4>&& conn) {
                std::cout << "Accepted again\n";
                std::array<char, 1024> buffer;
                conns.push_back(std::move(conn));
                auto& sock = conns.back();

                sock.async_read(net::span {buffer}, [&buffer](size_t br) {
                    std::cout << "Received: " << br << " -.- " << std::string_view {buffer.data(), br} << '\n';
                });
            });
        });

        std::cout << "Wait for data ...\n";
        // std::this_thread::sleep_for(std::chrono::milliseconds(10000));
        net::async_context::instance().run();
    }
    else if(strcmp(argv[1], "s") == 0)
    {
        {
            std::cout << "--- Sender ---\n";
            net::tcp_connection<net::ip_version::v4> sock {"127.0.0.1", 4433};
            std::cout << "Connected\n";
            std::vector<char> vec {'H', 'e', 'l', 'l', 'o'};

            std::this_thread::sleep_for(std::chrono::milliseconds(2000));
            std::string_view buffer {"Hello String_view-World"};
            sock.send(net::span {buffer.begin(), buffer.end()});
            std::cout << "Sent\n";

            std::this_thread::sleep_for(std::chrono::milliseconds(1000));
            sock.send(net::span {std::string_view {"Test, test, 123"}});
        }
        {
            std::cout << "--- Sender ---\n";
            net::tcp_connection<net::ip_version::v4> sock {"127.0.0.1", 4433};
            std::cout << "Connected\n";
            std::vector<char> vec {'H', 'e', 'l', 'l', 'o'};
            // sock.send(net::span {vec});
            // sock.send(net::span {std::string {"Hello World"}});

            std::this_thread::sleep_for(std::chrono::milliseconds(2000));
            std::string_view buffer {"Hello world from the second accepted connection!"};
            sock.send(net::span {buffer.begin(), buffer.end()});

            std::cout << "Sent\n";
        }
    }
}
