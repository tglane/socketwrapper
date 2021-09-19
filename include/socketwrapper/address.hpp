#ifndef SOCKETWRAPPER_NET_ADDRESS_HPP
#define SOCKETWRAPPER_NET_ADDRESS_HPP

#include "detail/utility.hpp"

#include <string>
#include <string_view>

namespace net {

/// Address class for ip v4/v6 address/endpoint abstraction
template <ip_version IP_VER>
class address;

/// Template specialization for ip v4 connections
template <>
class address<ip_version::v4>
{
public:
    using addr_type = sockaddr_in;
    static constexpr const size_t addr_size = sizeof(sockaddr_in);

    address() = default;

    explicit address(const sockaddr_in& addr)
        : m_up_to_date {true}
        , m_addr {addr}
    {
        std::tie(m_addr_string, m_port) =
            detail::resolve_addrinfo<ip_version::v4>(reinterpret_cast<const sockaddr*>(&m_addr));
    }

    address(std::string_view addr, uint16_t port, socket_type conn_type)
        : m_up_to_date {true}
        , m_addr {std::get<sockaddr_in>(detail::resolve_hostname<ip_version::v4>(addr, port, conn_type))}
        , m_addr_string {addr.begin(), addr.end()}
        , m_port {port}
    {}

    const std::string& get_addr_string() const
    {
        update();
        return m_addr_string;
    }

    uint16_t get_port() const
    {
        update();
        return m_port;
    }

    const sockaddr& get_addr() const
    {
        return *reinterpret_cast<const sockaddr*>(&m_addr);
    }

    sockaddr& get_addr()
    {
        m_up_to_date = false;
        return *reinterpret_cast<sockaddr*>(&m_addr);
    }

private:
    void update() const
    {
        if(!m_up_to_date)
        {
            std::tie(m_addr_string, m_port) =
                detail::resolve_addrinfo<ip_version::v4>(reinterpret_cast<const sockaddr*>(&m_addr));
            m_up_to_date = true;
        }
    }

    mutable bool m_up_to_date = false;
    sockaddr_in m_addr;
    mutable std::string m_addr_string;
    mutable uint16_t m_port;
};

/// Template specialization for ip v6 connections
template <>
class address<ip_version::v6>
{
public:
    using addr_type = sockaddr_in6;
    static constexpr const size_t addr_size = sizeof(sockaddr_in6);

    address() = default;

    explicit address(const sockaddr_in6& addr)
        : m_up_to_date {true}
        , m_addr {addr}
    {
        std::tie(m_addr_string, m_port) =
            detail::resolve_addrinfo<ip_version::v6>(reinterpret_cast<const sockaddr*>(&m_addr));
    }

    address(std::string_view addr, uint16_t port, socket_type conn_type)
        : m_up_to_date {true}
        , m_addr {std::get<sockaddr_in6>(detail::resolve_hostname<ip_version::v6>(addr, port, conn_type))}
        , m_addr_string {addr.begin(), addr.end()}
        , m_port {port}
    {}

    const std::string& get_addr_string() const
    {
        update();
        return m_addr_string;
    }

    uint16_t get_port() const
    {
        update();
        return m_port;
    }

    const sockaddr& get_addr() const
    {
        return *reinterpret_cast<const sockaddr*>(&m_addr);
    }

    sockaddr& get_addr()
    {
        m_up_to_date = false;
        return *reinterpret_cast<sockaddr*>(&m_addr);
    }

private:
    void update() const
    {
        if(!m_up_to_date)
        {
            std::tie(m_addr_string, m_port) =
                detail::resolve_addrinfo<ip_version::v6>(reinterpret_cast<const sockaddr*>(&m_addr));
            m_up_to_date = true;
        }
    }

    mutable bool m_up_to_date = false;
    sockaddr_in6 m_addr;
    mutable std::string m_addr_string;
    mutable uint16_t m_port;
};

/// Shorthand using-declarations for addresses template specializations
using address_v4 = address<ip_version::v4>;
using address_v6 = address<ip_version::v6>;

} // namespace net

#endif
