#include "../include/socketwrapper/tls.hpp"
#include "../include/socketwrapper/utility.hpp"
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
        auto acceptor = net::tls_acceptor_v4("./cert.pem", "./key.pem", net::endpoint_v4("0.0.0.0", 4433));

        auto sock_fut = acceptor.promised_accept();
        std::cout << "Got future socket\n";
        auto conn = sock_fut.get();
        auto buffer = std::array<char, 1024>{};
        conn.async_read(net::span{buffer},
            [&buffer](size_t br, std::exception_ptr) {
                std::cout << "Received " << br << " bytes -- " << std::string_view{buffer.data(), br} << '\n';
            });

        net::async_run();
    }
    else if (strcmp(argv[1], "s") == 0)
    {
        std::cout << "--- Sender ---\n";
        auto tls_sock =
            net::tls_connection<net::ip_version::v4>("./cert.pem", "./key.pem", net::endpoint_v4("127.0.0.1", 4433));

        tls_sock.promised_send(net::span{"Hello world"}).get();
        std::cout << "TLS encrypted message sent\n";
    }
}
