#include "../include/socketwrapper/promise.hpp"
#include "../include/socketwrapper/task.hpp"
#include "../include/socketwrapper/udp.hpp"

#include <chrono>
#include <iostream>
#include <string_view>

net::task<size_t> handle_receive(const net::udp_socket_v4& sock, net::span<char> buffer)
{
    auto res = co_await sock.co_read(buffer);
    co_return res.first;
}

net::promise<size_t> receiver(int port)
{
    auto buffer = std::array<char, 1024>{};
    auto sock = net::udp_socket_v4(net::endpoint_v4("0.0.0.0", port));

    size_t package_cnt = 0;
    while (true)
    {
        try
        {
            package_cnt++;
            const auto bytes_recv = co_await handle_receive(sock, net::span(buffer));
            std::cout << "Received on port " << port << ": " << std::string_view(buffer.data(), bytes_recv) << '\n';

            if (bytes_recv == 1 && buffer[0] == 0)
            {
                std::cout << "Client closed connection\n";
                break;
            }
        }
        catch (const std::exception& ex)
        {
            std::cout << "Exception occured in read: " << ex.what() << '\n';
            break;
        }
    }
    co_return package_cnt;
}

net::promise<void> sender(int port)
{
    auto sock = net::udp_socket_v4();

    auto msg = std::string_view("Hello coroutine!");
    for (int i = 0; i < 10; i++)
    {
        std::this_thread::sleep_for(std::chrono::milliseconds(1000));
        co_await sock.co_write(net::endpoint_v4("127.0.0.1", port), net::span(msg));
    }

    uint8_t close_byte = 0;
    co_await sock.co_write(net::endpoint_v4("127.0.0.1", port), net::span(&close_byte, 1));
}

int main()
{
    // auto p1 = net::spawn(receiver(4433));
    // auto p2 = net::spawn(sender(4433));
    auto p1 = receiver(4433);
    auto p2 = sender(4433);

    net::async_run();
}
