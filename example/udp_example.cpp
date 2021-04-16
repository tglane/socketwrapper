#include "../socketwrapper.hpp"
#include <iostream>
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
        // net::connection_info peer;
        // size_t bytes_read = sock.read(net::span {buffer}, peer);
        auto [bytes_read, peer] = sock.read(net::span {buffer});
        std::cout << "Peer addr: " << peer.addr << "; Peer port: " << peer.port << "; Bytes read: " << bytes_read << '\n';
        std::cout << std::string_view {buffer.data(), bytes_read} << '\n';
   }
    else if(strcmp(argv[1], "s") == 0)
    {
        std::cout << "--- Sender ---\n";
        net::udp_socket<net::ip_version::v4> sock {};
        std::string buffer {"Hello world"};
        sock.send("127.0.0.1", 4433, net::span {buffer});
        std::cout << "All messages sent." << std::endl;
    }
}
