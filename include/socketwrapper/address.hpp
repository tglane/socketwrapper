#ifndef SOCKETWRAPPER_NET_ADDRESS_HPP
#define SOCKETWRAPPER_NET_ADDRESS_HPP

#include "detail/utility.hpp"

#include <string_view>

namespace net {

template <ip_version IP_VER>
class address;

template <>
class address<ip_version::v4>
{
public:
    address(std::string_view addr, uint16_t port, socket_type conn_type)
        : m_addr {std::get<sockaddr_in>(detail::resolve_hostname(addr, port, conn_type))}
    {}

    connection_info connection_info() const
    {
        return detail::resolve_addrinfo(reinterpret_cast<const sockaddr*>(&m_addr));
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

template <>
class address<ip_version::v6>
{
public:
    address(std::string_view addr, uint16_t port, socket_type conn_type)
        : m_addr {std::get<sockaddr_in6>(detail::resolve_hostname(addr, port, conn_type))}
    {}

    connection_info connection_info() const
    {
        return detail::resolve_addrinfo(reinterpret_cast<const sockaddr*>(&m_addr));
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

} // namespace net

#endif
