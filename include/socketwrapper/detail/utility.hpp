#ifndef SOCKETWRAPPER_NET_INTERNAL_UTILITY_HPP
#define SOCKETWRAPPER_NET_INTERNAL_UTILITY_HPP

#include <array>
#include <charconv>
#include <csignal>
#include <cstddef>
#include <cstdint>
#include <fstream>
#include <memory>
#include <stdexcept>
#include <string_view>
#include <variant>

#include <arpa/inet.h>
#include <netdb.h>

namespace net {

enum class ip_version : uint8_t
{
    v4 = AF_INET,
    v6 = AF_INET6
};

enum class socket_type : uint8_t
{
    unspecified = AF_UNSPEC,
    stream = SOCK_STREAM,
    datagram = SOCK_DGRAM
};

template <ip_version ip_ver_v>
class endpoint;

namespace detail {

template <ip_version ip_ver_v>
inline auto resolve_hostname(std::string_view host_name, uint16_t port, socket_type type = socket_type::unspecified)
{
    addrinfo hints{};
    hints.ai_family = static_cast<uint8_t>(ip_ver_v);
    hints.ai_socktype = static_cast<uint8_t>(type);

    std::array<char, 6> port_buffer{0, 0, 0, 0, 0, '\0'};
    auto [_, ec] = std::to_chars(port_buffer.begin(), port_buffer.end(), port);
    if (ec != std::errc())
        throw std::runtime_error{"Ill formed address."};

    std::string_view port_str{port_buffer.begin(), std::distance(port_buffer.begin(), port_buffer.end())};
    std::unique_ptr<addrinfo, decltype(&::freeaddrinfo)> resultlist_owner{nullptr, &::freeaddrinfo};
    addrinfo* tmp_resultlist = resultlist_owner.get();

    int ret;
    ret = ::getaddrinfo(host_name.data(), port_str.data(), &hints, &tmp_resultlist);
    resultlist_owner.reset(tmp_resultlist);

    if (ret == 0)
        return reinterpret_cast<typename endpoint<ip_ver_v>::addr_type&>(*resultlist_owner->ai_addr);
    else
        throw std::runtime_error{"Error while resolving hostname."};
}

template <ip_version ip_ver_v>
inline std::pair<std::string, uint16_t> resolve_addrinfo(const sockaddr* addr_in)
{
    std::pair<std::string, uint16_t> peer{};
    peer.first.resize(endpoint<ip_ver_v>::addr_str_len);

    std::array<char, NI_MAXSERV> port_buffer;

    // Parse the ip address represented by addr_in
    if (::getnameinfo(addr_in,
            endpoint<ip_ver_v>::addr_size,
            peer.first.data(),
            peer.first.capacity(),
            port_buffer.data(),
            port_buffer.size(),
            NI_NUMERICHOST | NI_NUMERICSERV) != 0)
    {
        throw std::runtime_error{"Failed to resolve address info."};
    }

    auto [_, ec] = std::from_chars(port_buffer.begin(), port_buffer.end(), peer.second);
    if (ec != std::errc())
        throw std::runtime_error{"Failed to resolve port."};

    return peer;
}

inline std::string read_file(std::string_view path)
{
    std::ifstream ifs{path.data()};
    std::string out;

    // Reserve memory up front
    ifs.seekg(0, std::ios::end);
    out.reserve(ifs.tellg());
    ifs.seekg(0, std::ios::beg);

    out.assign({std::istreambuf_iterator<char>{ifs}, std::istreambuf_iterator<char>{}});
    return out;
}

inline void init_socket_system()
{
    static bool initialized = false;
    if (!initialized)
    {
        std::signal(SIGPIPE, SIG_IGN);

        initialized = true;
    }
}

template <typename data_type>
constexpr inline data_type swap_byteorder(data_type in)
{
    data_type out;
    constexpr size_t limit = sizeof(data_type);
    uint8_t* in_ptr = reinterpret_cast<uint8_t*>(&in);
    uint8_t* out_ptr = reinterpret_cast<uint8_t*>(&out);

    for (size_t i = 0; i < limit; ++i)
        out_ptr[i] = in_ptr[limit - i - 1];

    return out;
}

template <typename data_type>
constexpr inline void swap_byteorder(const data_type* in, data_type* out, size_t elements)
{
    size_t limit = sizeof(data_type) * elements;
    for (size_t i = 0; i < limit; ++i)
        out[i] = in[limit - i - 1];
}

} // namespace detail

} // namespace net

#endif
