#include "../include/socketwrapper/udp.hpp"
#include <iostream>
#include <thread>
#include <cstring>

int main(int argc, char** argv)
{
    if(argc <= 1)
        return 0;

    if(strcmp(argv[1], "r") == 0)
    {
        std::cout << "--- Receiver ---\n";
        net::udp_socket<net::ip_version::v4> sock {"0.0.0.0", 4433};
        std::array<char, 1024> buffer;

        std::array<char, 1024> buffer_two;
        auto read_fut = sock.promised_read(net::span {buffer_two});
        std::this_thread::sleep_for(std::chrono::milliseconds(3000));

        sock.async_read(net::span {buffer}, [&sock, &buffer](size_t bytes) {
            std::cout << "Received " << bytes << " bytes. -- " << std::string_view {buffer.data(), bytes} << '\n';

            sock.async_read(net::span {buffer}, [&buffer](size_t bytes) {
                std::cout << "Inner received " << bytes << " bytes. -- " << std::string_view {buffer.data(), bytes} << '\n';
            });
        });

        sock.async_read(net::span {buffer}, [&sock, &buffer](size_t bytes) {
            std::cout << "Received " << bytes << " bytes. -- " << std::string_view {buffer.data(), bytes} << '\n';

            sock.async_read(net::span {buffer}, [&buffer](size_t bytes) {
                std::cout << "Inner received " << bytes << " bytes. -- " << std::string_view {buffer.data(), bytes} << '\n';
            });
        });

        if (read_fut.valid())
        {
            read_fut.wait();
            std::cout << "Finished waiting\n";

            auto read_ret = read_fut.get();
            std::cout << "Received promised read with " << read_ret.first << " bytes. -- "
               << std::string_view {buffer_two.data(), read_ret.first} << '\n';
        }
        else
        {
            std::cout << "Read future invalid ...\n";
        }

        std::cout << "Waiting ...\n";
        std::this_thread::sleep_for(std::chrono::milliseconds(10000));
    }
    else if(strcmp(argv[1], "s") == 0)
    {
        std::cout << "--- Sender ---\n";
        net::udp_socket<net::ip_version::v4> sock {};

        std::string str {"Hello async UDP world!"};
        sock.send("127.0.0.1", 4433, net::span {str});

        sock.send("127.0.0.1", 4433, net::span {"KekW"});
        std::cout << "All messages sent!\n";

        std::this_thread::sleep_for(std::chrono::milliseconds(2000));
        sock.send("127.0.0.1", 4433, net::span {str});
        std::cout << "Another message sent!\n";
    }
}
