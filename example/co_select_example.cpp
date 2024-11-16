#include "../include/socketwrapper/select.hpp"
#include "../include/socketwrapper/task.hpp"
#include "../include/socketwrapper/udp.hpp"
#include <iostream>

net::task<void> co_main()
{
    auto sock_one = net::udp_socket_v4();
    auto sock_two = net::udp_socket_v4();

    // Block until the first of the passed in coroutines finishes and execute it
    // The remaining coroutines will get dropped and not executed
    co_await net::select(
        [&sock_one]() -> net::task<void>
        {
            auto buffer = std::array<char, 1024>{};
            co_await sock_one.async_read(net::span(buffer));
            std::cout << "Read from first socket\n";
        },
        [&sock_two]() -> net::task<void>
        {
            auto buffer = std::array<char, 1024>{};
            co_await sock_two.async_read(net::span(buffer));
            std::cout << "Read from second socket\n";
        });
}

int main()
{
    net::block_on(co_main());
}
