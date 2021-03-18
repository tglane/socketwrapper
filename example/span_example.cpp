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

    std::vector<char> vec {'H', 'e', 'l', 'l', 'o'};
    // net::span<char> s_four {vec.begin(), vec.end()};
    net::span<char> s_four {vec};
    std::cout << std::prev(s_four.end()) << '\n' << std::endl;
    for(const auto& it : s_four)
        std::cout << it << '\n';
}

