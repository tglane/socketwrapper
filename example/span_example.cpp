#include "../include/socketwrapper/span.hpp"
#include <iostream>
#include <string>
#include <vector>

int main()
{
    int ix[5] = {3, 5, 3, 77, 11};
    auto s_one = net::span{ix};

    std::cout << "Size of span from int[5]: " << s_one.size() << '\n';

    auto empty_vec = std::vector<char>{};
    auto empty_span = net::span{empty_vec};
    std::cout << "empty_span.empty() = " << empty_span.empty() << '\n';

    auto str = std::string{"Hello World"};
    auto s_two = net::span{str.begin(), str.end()};

    auto s_three = net::span{str.c_str(), 4};

    auto vec = std::vector<char>{'H', 'e', 'l', 'l', 'o'};
    auto s_four = net::span{vec};
    std::cout << *std::prev(std::end(s_four)) << '\n' << std::endl;
    for (const auto& it : s_four)
    {
        std::cout << it << '\n';
    }

    auto s_five = net::span{&(ix[0]), &(ix[4])};

    auto s_six = net::span{str};
}
