#include "../include/socketwrapper/promise.hpp"
#include "../include/socketwrapper/task.hpp"
#include "../include/socketwrapper/tcp.hpp"

#include <array>
#include <cstring>
#include <iostream>
#include <span>
#include <string_view>

net::task<size_t> handle_connection(net::tcp_connection_v4 conn)
{
    std::cout << "Waiting for data on socket " << conn.get() << '\n';
    size_t total_bytes = -1;
    auto buffer = std::array<char, 1024>{};

    auto fut = conn.co_read(net::span(buffer));
    while (true)
    {
        std::cout << "Awaiting read fut\n";
        auto bytes_read = co_await fut;
        if (bytes_read == 0)
        {
            std::cout << "Connection on " << conn.get() << " closed by client\n";
            co_return total_bytes;
        }

        std::cout << "Read " << std::string_view(buffer.data(), bytes_read) << " on socket " << conn.get() << '\n';
        total_bytes += bytes_read;
    }
    co_return total_bytes;
}

net::promise<void> accept_loop(net::endpoint_v4 bind_addr)
{
    const auto listener = net::tcp_acceptor_v4(std::move(bind_addr));
    while (true)
    {
        auto conn = co_await listener.co_accept();
        // Handle every connection asynchronously
        net::spawn(handle_connection(std::move(conn)));
    }
}

net::promise<void> connect(net::endpoint_v4 conn_addr)
{
    auto sock = net::tcp_connection_v4();
    co_await sock.co_connect(std::move(conn_addr));

    std::cout << "Connected\n";

    auto msg = std::string_view("Hello, my dear friend");
    co_await sock.co_write(net::span(msg));
}

int main()
{
    auto p1 = accept_loop(net::endpoint_v4("0.0.0.0", 4433));
    auto p2 = connect(net::endpoint_v4("127.0.0.1", 4433));

    net::async_run();
}
