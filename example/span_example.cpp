#include "../include/socketwrapper/span.hpp"
#include <iostream>
#include <string>
#include <vector>

int main()
{
    int ix[5] = {3, 5, 3, 77, 11};
    net::span s_one{ix};

    std::cout << "Size of span from int[5]: " << s_one.size() << '\n';

    std::vector<char> empty_vec{};
    net::span empty_span{empty_vec};
    std::cout << "empty_span.empty() = " << empty_span.empty() << '\n';

    std::string str{"Hello World"};
    net::span s_two{str.begin(), str.end()};

    net::span s_three{str.c_str(), 4};

    std::vector<char> vec{'H', 'e', 'l', 'l', 'o'};
    net::span s_four{vec};
    std::cout << *std::prev(std::end(s_four)) << '\n' << std::endl;
    for(const auto& it : s_four)
        std::cout << it << '\n';

    net::span s_five{&(ix[0]), &(ix[4])};

    net::span s_six{str};
}
