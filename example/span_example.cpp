#include "../socketwrapper.hpp"

#include <string>
#include <vector>
#include <iostream>

int main()
{
    int ix[5] = {3, 5, 3, 77, 11};
    net::span s_one {ix};
    std::cout << s_one.size() << '\n';

    std::string str {"Hello World"};
    net::span<char> s_two {str.begin(), str.end()};

    net::span s_three {str.c_str(), 4};
}

