#include "../include/socketwrapper/tcp.hpp"

#include <array>
#include <cstring>
#include <iostream>
#include <string_view>
#include <thread>

int main()
{
    std::cout << "--- Options example ---\n";

    auto acceptor = net::tcp_acceptor_v4(net::endpoint_v4("0.0.0.0", 4433));

    // Set and get socket option example socket option for receive buffer size
    acceptor.set_option(net::option<net::option_level::socket, SO_RCVBUF, int>{10000});
    auto recv_buff_size = acceptor.get_option_value<net::option<net::option_level::socket, SO_RCVBUF, int>>();
    std::cout << "Recvbuff size for accepting socket: " << recv_buff_size << '\n';

    acceptor.async_accept(
        [](auto sock, std::exception_ptr)
        {
            auto buffer = std::array<char, 1024>{};
            auto len = sock.read(net::span(buffer));
            std::cout << "Message read: " << std::string_view(buffer.data(), len) << '\n';
        });

    auto test_con = net::tcp_connection_v4(net::endpoint_v4("127.0.0.1", 4433, net::socket_type::stream));
    test_con.send(net::span{std::string_view{"Hello world"}});

    // Get the peer security ctx
    // auto peer_ctx_opt = test_con.get_option<net::option<net::option_level::socket, SO_PEERSEC, char>>();
    // std::cout << peer_ctx_opt.value() << '\n';

    std::this_thread::sleep_for(std::chrono::milliseconds(1000));
}
