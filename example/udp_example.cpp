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
        auto buffer = sock.read<char>(512);
        std::cout << std::string_view {buffer.data(), buffer.size() } << '\n';
   }
    else if(strcmp(argv[1], "s") == 0)
    {
        std::cout << "--- Sender ---\n";
        net::udp_socket<net::ip_version::v4> sock {};
        // std::vector<char> buffer {'h', 'a', 'l', 'l', 'o'};
        std::string_view buffer {"Hello world lololo"};
        sock.send("127.0.0.1", 4433, buffer);
        std::cout << "All messages sent." << std::endl;
    }
}

