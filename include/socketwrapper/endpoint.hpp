#ifndef SOCKETWRAPPER_NET_endpoint_HPP
#define SOCKETWRAPPER_NET_endpoint_HPP

#include "./utility.hpp"

#include <algorithm>
#include <cstddef>
#include <string>
#include <cstring>
#include <string_view>
#include <sys/un.h>

namespace net {

/// Class for an abstraction of a ip v4/v6 connection to a specific port.
template <ip_version IP_VER>
class endpoint;

/// Template specialization for ip v4 connections
template <>
class endpoint<ip_version::v4>
{
    mutable bool m_up_to_date = false;

    sockaddr_in m_addr;

    mutable std::string m_addr_string;

    mutable uint16_t m_port;

    void update() const
    {
        if (!m_up_to_date)
        {
            std::tie(m_addr_string, m_port) =
                detail::resolve_addrinfo<ip_version::v4>(reinterpret_cast<const sockaddr*>(&m_addr));
            m_up_to_date = true;
        }
    }

public:
    using addr_type = sockaddr_in;
    static constexpr const size_t addr_size = sizeof(sockaddr_in);
    static constexpr const size_t addr_str_len = INET_ADDRSTRLEN;
    static constexpr const int addr_family = AF_INET;

    endpoint() = default;

    explicit endpoint(const sockaddr_in& addr)
        : m_up_to_date{true}
        , m_addr{addr}
    {
        std::tie(m_addr_string, m_port) =
            detail::resolve_addrinfo<ip_version::v4>(reinterpret_cast<const sockaddr*>(&m_addr));
    }

    endpoint(std::string_view addr, uint16_t port, socket_type conn_type = socket_type::unspecified)
        : m_up_to_date{true}
        , m_addr{detail::resolve_hostname<ip_version::v4>(addr, port, conn_type)}
        , m_addr_string{addr.begin(), addr.end()}
        , m_port{port}
    {}

    endpoint(const std::array<uint8_t, 4>& addr_bytes, uint16_t port)
        : m_up_to_date{false}
        , m_addr{}
        , m_addr_string{}
        , m_port{}
    {
        m_addr.sin_port = host_to_network<uint16_t>(port);
        m_addr.sin_family = static_cast<uint8_t>(ip_version::v4);
        std::copy_n(addr_bytes.data(), 4, reinterpret_cast<uint8_t*>(&m_addr.sin_addr.s_addr));

        update();
    }

    endpoint(uint8_t (&addr_bytes)[4], uint16_t port)
        : m_up_to_date{false}
        , m_addr{}
        , m_addr_string{}
        , m_port{}
    {
        m_addr.sin_port = host_to_network<uint16_t>(port);
        m_addr.sin_family = static_cast<uint8_t>(ip_version::v4);
        std::copy_n(addr_bytes, 4, reinterpret_cast<uint8_t*>(&m_addr.sin_addr.s_addr));

        update();
    }

    const std::string& get_addr_string() const
    {
        update();
        return m_addr_string;
    }

    std::array<uint8_t, 4> get_addr_bytes() const
    {
        auto bytes = std::array<uint8_t, 4>{};
        std::copy_n(reinterpret_cast<const uint8_t*>(&m_addr.sin_addr.s_addr), 4, bytes.data());
        return bytes;
    }

    uint16_t get_port() const
    {
        update();
        return m_port;
    }

    const sockaddr& get_addr() const
    {
        return reinterpret_cast<const sockaddr&>(m_addr);
    }

    sockaddr& get_addr()
    {
        m_up_to_date = false;
        return reinterpret_cast<sockaddr&>(m_addr);
    }

    inline bool is_valid_addr_size(size_t s)
    {
        return s == addr_size;
    }
};

/// Template specialization for ip v6 connections
template <>
class endpoint<ip_version::v6>
{
    mutable bool m_up_to_date = false;

    sockaddr_in6 m_addr;

    mutable std::string m_addr_string;

    mutable uint16_t m_port;

    void update() const
    {
        if (!m_up_to_date)
        {
            std::tie(m_addr_string, m_port) =
                detail::resolve_addrinfo<ip_version::v6>(reinterpret_cast<const sockaddr*>(&m_addr));
            m_up_to_date = true;
        }
    }

public:
    using addr_type = sockaddr_in6;
    static constexpr const size_t addr_size = sizeof(sockaddr_in6);
    static constexpr const size_t addr_str_len = INET6_ADDRSTRLEN;
    static constexpr const int addr_family = AF_INET6;

    endpoint() = default;

    explicit endpoint(const sockaddr_in6& addr)
        : m_up_to_date{true}
        , m_addr{addr}
    {
        std::tie(m_addr_string, m_port) =
            detail::resolve_addrinfo<ip_version::v6>(reinterpret_cast<const sockaddr*>(&m_addr));
    }

    endpoint(std::string_view addr, uint16_t port, socket_type conn_type = socket_type::unspecified)
        : m_up_to_date{true}
        , m_addr{detail::resolve_hostname<ip_version::v6>(addr, port, conn_type)}
        , m_addr_string{addr.begin(), addr.end()}
        , m_port{port}
    {}

    endpoint(const std::array<uint8_t, 16>& addr_bytes, uint16_t port)
        : m_up_to_date{false}
        , m_addr{}
        , m_addr_string{}
        , m_port{}
    {
        m_addr.sin6_port = host_to_network<uint16_t>(port);
        m_addr.sin6_family = static_cast<uint8_t>(ip_version::v4);
        std::copy_n(addr_bytes.data(), 16, reinterpret_cast<uint8_t*>(&m_addr.sin6_addr.s6_addr));

        update();
    }

    endpoint(uint8_t (&addr_bytes)[16], uint16_t port)
        : m_up_to_date{false}
        , m_addr{}
        , m_addr_string{}
        , m_port{}
    {
        m_addr.sin6_port = host_to_network<uint16_t>(port);
        m_addr.sin6_family = static_cast<uint8_t>(ip_version::v4);
        std::copy_n(addr_bytes, 16, reinterpret_cast<uint8_t*>(&m_addr.sin6_addr.s6_addr));

        update();
    }

    const std::string& get_addr_string() const
    {
        update();
        return m_addr_string;
    }

    std::array<uint8_t, 16> get_addr_bytes() const
    {
        auto bytes = std::array<unsigned char, 16>{};
        std::copy_n(reinterpret_cast<const uint8_t*>(&m_addr.sin6_addr.s6_addr), 16, bytes.data());
        return bytes;
    }

    uint16_t get_port() const
    {
        update();
        return m_port;
    }

    const sockaddr& get_addr() const
    {
        return reinterpret_cast<const sockaddr&>(m_addr);
    }

    sockaddr& get_addr()
    {
        m_up_to_date = false;
        return reinterpret_cast<sockaddr&>(m_addr);
    }

    inline bool is_valid_addr_size(size_t s)
    {
        return s == addr_size;
    }
};


/// Template specialization for unix connections
template <>
class endpoint<ip_version::unixsock>
{
    sockaddr_un m_addr;

public:
    using addr_type = sockaddr_un;
    static constexpr const size_t addr_size = sizeof(sockaddr_un);
    static constexpr const size_t addr_str_len = sizeof(sockaddr_un::sun_path);
    static constexpr const int addr_family = AF_UNIX;

    endpoint() = default;

    explicit endpoint(const sockaddr_un& addr)
     : m_addr(addr)
    {

    }

    explicit endpoint(const char* path)
    {
        int n = strlen(path);
        if(n >= (int)addr_str_len - 1)
            throw std::invalid_argument("path is too long");
        m_addr.sun_family = AF_UNIX;
        std::memcpy(m_addr.sun_path, path, n);
    }

    std::string get_addr_string() const
    {
        return std::string(m_addr.sun_path);
    }

    std::array<uint8_t, addr_str_len> get_addr_bytes() const
    {
        auto bytes = std::array<uint8_t, addr_str_len>{};
        std::copy_n(m_addr.sun_path, addr_str_len, bytes.data());
        return bytes;
    }


    const sockaddr& get_addr() const
    {
        return reinterpret_cast<const sockaddr&>(m_addr);
    }

    sockaddr& get_addr()
    {
        return reinterpret_cast<sockaddr&>(m_addr);
    }

    inline bool is_valid_addr_size(size_t s)
    {
        return s <= addr_size;
    }
};

/// Shorthand using-declarations for endpoint class template specializations
using endpoint_v4 = endpoint<ip_version::v4>;
using endpoint_v6 = endpoint<ip_version::v6>;
using endpoint_unix = endpoint<ip_version::unixsock>;

} // namespace net

#endif
