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
    net::span s_two {str.begin(), str.end()};

    net::span s_three {str.c_str(), 4};

    std::vector<char> vec {'H', 'e', 'l', 'l', 'o'};
    net::span s_four {vec};
    std::cout << *std::prev(end(s_four)) << '\n' << std::endl;
    for(const auto& it : s_four)
        std::cout << it << '\n';

    net::span s_five {&(ix[0]), &(ix[4])};

    net::span s_six {str};
}

