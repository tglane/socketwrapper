#ifndef SOCKETWRAPPER_NET_ADDRESS_HPP
#define SOCKETWRAPPER_NET_ADDRESS_HPP

#include "detail/utility.hpp"

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
    static constexpr const size_t addr_size = sizeof(sockaddr_in);

    address() = default;

    explicit address(const sockaddr_in& sockaddr)
        : m_addr {sockaddr}
    {}

    address(std::string_view addr, uint16_t port, socket_type conn_type)
        : m_addr {std::get<sockaddr_in>(detail::resolve_hostname<ip_version::v4>(addr, port, conn_type))}
    {}

    connection_info connection_info() const
    {
        return detail::resolve_addrinfo<ip_version::v4>(reinterpret_cast<const sockaddr*>(&m_addr));
    }

    const sockaddr& get_addr() const
    {
        return *reinterpret_cast<const sockaddr*>(&m_addr);
    }

    sockaddr& get_addr()
    {
        return *reinterpret_cast<sockaddr*>(&m_addr);
    }

private:
    sockaddr_in m_addr;
};

/// Template specialization for ip v6 connections
template <>
class address<ip_version::v6>
{
public:
    static constexpr const size_t addr_size = sizeof(sockaddr_in6);

    address() = default;

    explicit address(const sockaddr_in6& sockaddr)
        : m_addr {sockaddr}
    {}

    address(std::string_view addr, uint16_t port, socket_type conn_type)
        : m_addr {std::get<sockaddr_in6>(detail::resolve_hostname<ip_version::v6>(addr, port, conn_type))}
    {}

    connection_info connection_info() const
    {
        return detail::resolve_addrinfo<ip_version::v6>(reinterpret_cast<const sockaddr*>(&m_addr));
    }

    const sockaddr& get_addr() const
    {
        return *reinterpret_cast<const sockaddr*>(&m_addr);
    }

    sockaddr& get_addr()
    {
        return *reinterpret_cast<sockaddr*>(&m_addr);
    }

private:
    sockaddr_in6 m_addr;
};

/// Shorthand using-declarations for addresses template specializations
using address_v4 = address<ip_version::v4>;
using address_v6 = address<ip_version::v6>;

} // namespace net

#endif
