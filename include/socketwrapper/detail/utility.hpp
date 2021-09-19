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
    stream = SOCK_STREAM,
    datagram = SOCK_DGRAM
};

namespace detail {

template <ip_version IP_VER>
inline std::variant<sockaddr_in, sockaddr_in6> resolve_hostname(
    std::string_view host_name, uint16_t port, socket_type type)
{
    std::variant<sockaddr_in, sockaddr_in6> addr_out;

    addrinfo hints {};
    hints.ai_family = static_cast<uint8_t>(IP_VER);
    hints.ai_socktype = static_cast<uint8_t>(type);

    std::array<char, 6> port_buffer {0, 0, 0, 0, 0, '\0'};
    auto [end_ptr, ec] = std::to_chars(port_buffer.begin(), port_buffer.end(), port);
    if(ec != std::errc())
        throw std::runtime_error {"Ill formed address."};

    std::string_view port_str {port_buffer.begin(), std::distance(port_buffer.begin(), port_buffer.end())};
    std::unique_ptr<addrinfo, decltype(&::freeaddrinfo)> resultlist_owner {nullptr, &::freeaddrinfo};
    addrinfo* tmp_resultlist = resultlist_owner.get();

    int ret;
    ret = ::getaddrinfo(host_name.data(), port_str.data(), &hints, &tmp_resultlist);
    resultlist_owner.reset(tmp_resultlist);

    if(ret == 0)
    {
        if constexpr(IP_VER == ip_version::v4)
        {
            addr_out = *reinterpret_cast<sockaddr_in*>(resultlist_owner->ai_addr);
        }
        else if constexpr(IP_VER == ip_version::v6)
            addr_out = *reinterpret_cast<sockaddr_in6*>(resultlist_owner->ai_addr);
        else
            static_assert(IP_VER == ip_version::v4 || IP_VER == ip_version::v6);

        return addr_out;
    }
    else
    {
        throw std::runtime_error {"Error while resolving hostname."};
    }
}

template <ip_version IP_VER>
inline std::pair<std::string, uint16_t> resolve_addrinfo(const sockaddr* addr_in)
{
    std::pair<std::string, uint16_t> peer {};
    if constexpr(IP_VER == ip_version::v4)
    {
        peer.first.resize(INET_ADDRSTRLEN);
        std::string port_str; // Use string instead of array here because std::stoi creates a string anyway
        port_str.resize(6);

        if(inet_ntop(AF_INET,
               &(reinterpret_cast<const sockaddr_in*>(addr_in)->sin_addr),
               peer.first.data(),
               peer.first.capacity()) == nullptr)
        {
            throw std::runtime_error {"Failed to resolve addrinfo."};
        }
        peer.second = ntohs(reinterpret_cast<const sockaddr_in*>(addr_in)->sin_port);

        return peer;
    }
    else if constexpr(IP_VER == ip_version::v6)
    {
        peer.first.resize(INET6_ADDRSTRLEN);
        std::string port_str; // Use string instead of array here because std::stoi creates a string anyway
        port_str.resize(6);

        if(inet_ntop(AF_INET,
               &(reinterpret_cast<const sockaddr_in6*>(addr_in)->sin6_addr),
               peer.first.data(),
               peer.first.capacity()) == nullptr)
        {
            throw std::runtime_error {"Failed to resolve addrinfo."};
        }
        peer.second = ntohs(reinterpret_cast<const sockaddr_in6*>(addr_in)->sin6_port);

        return peer;
    }
    else
    {
        static_assert(IP_VER == ip_version::v4 || IP_VER == ip_version::v6);
    }
}

inline std::string read_file(std::string_view path)
{
    std::ifstream ifs {path.data()};
    std::string out;

    // Reserve memory up front
    ifs.seekg(0, std::ios::end);
    out.reserve(ifs.tellg());
    ifs.seekg(0, std::ios::beg);

    out.assign({std::istreambuf_iterator<char> {ifs}, std::istreambuf_iterator<char> {}});
    return out;
}

inline void init_socket_system()
{
    static bool initialized = false;
    if(!initialized)
    {
        std::signal(SIGPIPE, SIG_IGN);

        initialized = true;
    }
}

template <typename T>
constexpr inline T swap_byteorder(T in)
{
    T out;
    constexpr size_t limit = sizeof(T);
    uint8_t* in_ptr = reinterpret_cast<uint8_t*>(&in);
    uint8_t* out_ptr = reinterpret_cast<uint8_t*>(&out);

    for(size_t i = 0; i < limit; ++i)
        out_ptr[i] = in_ptr[limit - i - 1];

    return out;
}

} // namespace detail

} // namespace net

#endif
