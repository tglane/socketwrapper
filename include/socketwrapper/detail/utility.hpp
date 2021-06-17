#ifndef SOCKETWRAPPER_NET_INTERNAL_UTILITY_HPP
#define SOCKETWRAPPER_NET_INTERNAL_UTILITY_HPP

#include <memory>
#include <fstream>
#include <array>
#include <string_view>
#include <variant>
#include <charconv>
#include <stdexcept>
#include <cstddef>
#include <cstdint>
#include <csignal>

#include <netdb.h>
#include <arpa/inet.h>

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

/// Struct containing connection data including a string representation of peers ip address and port
struct connection_info
{
    std::string addr;
    uint16_t port;
};

namespace detail {

template<ip_version IP_VER>
inline int resolve_hostname(std::string_view host_name, uint16_t port, socket_type type, std::variant<sockaddr_in, sockaddr_in6>& addr_out)
{
    int ret;

    addrinfo hints {};
    hints.ai_family = static_cast<uint8_t>(IP_VER);
    hints.ai_socktype = static_cast<uint8_t>(type);

    std::array<char, 6> port_buffer {0, 0, 0, 0, 0, '\0'};
    auto [end_ptr, ec] = std::to_chars(port_buffer.begin(), port_buffer.end(), port);
    if(ec != std::errc())
        return -1;

    std::string_view port_str {port_buffer.begin(), std::distance(port_buffer.begin(), port_buffer.end())};

    std::unique_ptr<addrinfo, decltype(&::freeaddrinfo)> resultlist_owner {nullptr, &::freeaddrinfo};
    addrinfo* tmp_resultlist = resultlist_owner.get();
    ret = ::getaddrinfo(host_name.data(), port_str.data(), &hints, &tmp_resultlist);
    resultlist_owner.reset(tmp_resultlist);

    if(ret == 0)
    {
        if constexpr(IP_VER == ip_version::v4) {
            addr_out = *reinterpret_cast<sockaddr_in*>(resultlist_owner->ai_addr);
        }
        else if constexpr(IP_VER == ip_version::v6)
            addr_out = *reinterpret_cast<sockaddr_in6*>(resultlist_owner->ai_addr);
        else
            static_assert(IP_VER == ip_version::v4 || IP_VER == ip_version::v6);
    }

    return ret;
}

template<ip_version IP_VER>
inline connection_info resolve_addrinfo(sockaddr* addr_in)
{
    connection_info peer {};
    if constexpr(IP_VER == ip_version::v4)
    {
        peer.addr.resize(INET_ADDRSTRLEN);
        std::string port_str; // Use string instead of array here because std::stoi creates a string anyway
        port_str.resize(6);

        if(inet_ntop(AF_INET, &(reinterpret_cast<sockaddr_in*>(addr_in)->sin_addr), peer.addr.data(), peer.addr.capacity()) == nullptr)
            throw std::runtime_error {"Failed to resolve addrinfo."};
        peer.port = ntohs(reinterpret_cast<sockaddr_in*>(addr_in)->sin_port);

        return peer;
    }
    else if constexpr(IP_VER == ip_version::v6)
    {
        peer.addr.resize(INET6_ADDRSTRLEN);
        std::string port_str; // Use string instead of array here because std::stoi creates a string anyway
        port_str.resize(6);

        if(inet_ntop(AF_INET, &(reinterpret_cast<sockaddr_in6*>(addr_in)->sin6_addr), peer.addr.data(), peer.addr.capacity()) == nullptr)
            throw std::runtime_error {"Failed to resolve addrinfo."};
        peer.port = ntohs(reinterpret_cast<sockaddr_in6*>(addr_in)->sin6_port);

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

    out.assign({std::istreambuf_iterator<char>{ifs}, std::istreambuf_iterator<char>{}});
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




template<typename T>
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
