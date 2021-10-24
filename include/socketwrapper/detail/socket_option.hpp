#ifndef SOCKETWRAPPER_NET_SOCKET_OPTION_HPP
#define SOCKETWRAPPER_NET_SOCKET_OPTION_HPP

#include <algorithm>
#include <array>
#include <climits>
#include <stdexcept>
#include <string_view>
#include <type_traits>

#include <netinet/in.h>
#include <netinet/tcp.h>

namespace net {

enum class socket_option : int
{
    debug = SO_DEBUG,
    accept_conn = SO_ACCEPTCONN,
    broadcast = SO_BROADCAST,
    reuse_addr = SO_REUSEADDR,
    reuse_port = SO_REUSEPORT,
    keep_alive = SO_KEEPALIVE,
    linger = SO_LINGER, // struct linger
    oob_inline = SO_OOBINLINE,
    send_buff_size = SO_SNDBUF,
    recv_buff_size = SO_RCVBUF,
    recv_buff_size_force = SO_RCVBUFFORCE,
    error = SO_ERROR,
    type = SO_TYPE,
    dont_route = SO_DONTROUTE,
    recv_lowat = SO_RCVLOWAT,
    recv_timeout = SO_RCVTIMEO, // struct timeval
    send_lowat = SO_SNDLOWAT,
    send_timeout = SO_SNDTIMEO, // struct timeval
    busy_poll = SO_BUSY_POLL,
    priority = SO_PRIORITY,
    peek_offset = SO_PEEK_OFF,
    peer_security_ctx = SO_PEERSEC,
    peer_credentials = SO_PEERCRED,
    pass_sec_msg = SO_PASSSEC,
    pass_credentials = SO_PASSCRED,
    select_cpu = SO_INCOMING_CPU
};

enum class ipv4_option : int
{
    user_supplied_header = IP_HDRINCL,
    options = IP_OPTIONS,
    type_of_service = IP_TOS,
    time_to_live = IP_TTL,
    multicast_interface = IP_MULTICAST_IF,
    multicast_time_to_live = IP_MULTICAST_TTL,
    multicast_loop = IP_MULTICAST_LOOP,
    multicast_add = IP_ADD_MEMBERSHIP,
    multicast_drop = IP_DROP_MEMBERSHIP
};

enum class ipv6_option : int
{
    address_format = IPV6_ADDRFORM,
    hop_limit = IPV6_HOPLIMIT,
    hop_options = IPV6_HOPOPTS,
    next_hop = IPV6_NEXTHOP,
    packet_info = IPV6_PKTINFO,
    multicast_interface = IPV6_MULTICAST_IF,
    multicast_hops = IPV6_MULTICAST_HOPS,
    multicast_loop = IPV6_MULTICAST_LOOP,
    multicast_add = IPV6_ADD_MEMBERSHIP,
    multicast_drop = IPV6_DROP_MEMBERSHIP
};

enum class tcp_option : int
{
    max_seg_size = TCP_MAXSEG,
    no_delay = TCP_NODELAY
};

namespace detail {

template <typename OPTION_TYPE>
struct option_level;

template <>
struct option_level<socket_option>
{
    static constexpr const int value = SOL_SOCKET;
};

template <>
struct option_level<ipv4_option>
{
    static constexpr const int value = IPPROTO_IP;
};

template <>
struct option_level<ipv6_option>
{
    static constexpr const int value = IPPROTO_IPV6;
};

template <>
struct option_level<tcp_option>
{
    static constexpr const int value = IPPROTO_TCP;
};

template <typename TEST_TYPE, template <typename> class REF_TYPE>
struct is_template_of : std::false_type
{};

template <template <typename> typename REF_TYPE, typename T>
struct is_template_of<REF_TYPE<T>, REF_TYPE> : std::true_type
{};

} // namespace detail

template <typename T>
class option;

template <>
class option<int>
{
public:
    using value_type = int;

    option(int name, int level)
        : m_name {name}
        , m_level {level}
    {}

    option(int name, int level, bool value)
        : m_name {name}
        , m_level {level}
        , m_value {value}
    {}

    template <typename OPTION_ENUM>
    option(OPTION_ENUM name)
        : m_name {static_cast<int>(name)}
        , m_level {detail::option_level<OPTION_ENUM>::value}
    {}

    template <typename OPTION_ENUM>
    option(OPTION_ENUM name, int val)
        : m_name {static_cast<int>(name)}
        , m_level {detail::option_level<OPTION_ENUM>::value}
        , m_value {val}
    {}

    const int& name() const
    {
        return m_name;
    }

    const int& level() const
    {
        return m_level;
    }

    const int& value() const
    {
        return m_value;
    }

    int& value()
    {
        return m_value;
    }

private:
    int m_name;
    int m_level;
    int m_value;
};

template <>
class option<char>
{
public:
    using value_type = char;

    option(int name, int level)
        : m_name {name}
        , m_level {level}
    {}

    option(int name, int level, std::string_view value)
        : m_name {name}
        , m_level {level}
    {
        if(value.size() <= NAME_MAX)
            std::copy_n(value.begin(), value.size(), m_value.begin());
        else
            throw std::runtime_error {"Failed to create option from string_view."};
    }

    template <typename OPTION_ENUM>
    option(OPTION_ENUM name)
        : m_name {static_cast<int>(name)}
        , m_level {detail::option_level<OPTION_ENUM>::value}
    {}

    template <typename OPTION_ENUM>
    option(OPTION_ENUM name, std::string_view value)
        : m_name {static_cast<int>(name)}
        , m_level {detail::option_level<OPTION_ENUM>::value}
    {
        if(value.size() <= NAME_MAX)
            std::copy_n(value.begin(), value.size(), m_value.begin());
        else
            throw std::runtime_error {"Failed to create option from string_view."};
    }

    const int& name() const
    {
        return m_name;
    }

    const int& level() const
    {
        return m_level;
    }

    const char& value() const
    {
        return m_value.front();
    }

    char& value()
    {
        return m_value.front();
    }

private:
    int m_name;
    int m_level;
    std::array<char, NAME_MAX> m_value;
};

template <>
class option<bool>
{
    using value_type = bool;

    option(int name, int level)
        : m_name {name}
        , m_level {level}
    {}

    option(int name, int level, bool value)
        : m_name {name}
        , m_level {level}
        , m_value {value}
    {}

    template <typename OPTION_ENUM>
    option(OPTION_ENUM name)
        : m_name {static_cast<int>(name)}
        , m_level {detail::option_level<OPTION_ENUM>::value}
    {}

    template <typename OPTION_ENUM>
    option(OPTION_ENUM name, bool val)
        : m_name {static_cast<int>(name)}
        , m_level {detail::option_level<OPTION_ENUM>::value}
        , m_value {val}
    {}
    const int& name() const
    {
        return m_name;
    }

    const int& level() const
    {
        return m_level;
    }

    const bool& value() const
    {
        return m_value;
    }

    bool& value()
    {
        return m_value;
    }

private:
    int m_name;
    int m_level;
    bool m_value;
};

template <>
class option<linger>
{
public:
    using value_type = linger;

    option(int name, int level)
        : m_name {name}
        , m_level {level}
    {}

    option(int name, int level, const linger& value)
        : m_name {name}
        , m_level {level}
        , m_value {value}
    {}

    template <typename OPTION_ENUM>
    option(OPTION_ENUM name)
        : m_name {static_cast<int>(name)}
        , m_level {detail::option_level<OPTION_ENUM>::value}
    {}

    template <typename OPTION_ENUM>
    option(OPTION_ENUM name, const linger& val)
        : m_name {static_cast<int>(name)}
        , m_level {detail::option_level<OPTION_ENUM>::value}
        , m_value {val}
    {}

    const int& name() const
    {
        return m_name;
    }

    const int& level() const
    {
        return m_level;
    }

    const linger& value() const
    {
        return m_value;
    }

    linger& value()
    {
        return m_value;
    }

private:
    int m_name;
    int m_level;
    linger m_value;
};

template <>
class option<sockaddr>
{
public:
    using value_type = sockaddr;

    option(int name, int level)
        : m_name {name}
        , m_level {level}
    {}

    option(int name, int level, const sockaddr& value)
        : m_name {name}
        , m_level {level}
        , m_value {value}
    {}

    template <typename OPTION_ENUM>
    option(OPTION_ENUM name)
        : m_name {static_cast<int>(name)}
        , m_level {detail::option_level<OPTION_ENUM>::value}
    {}

    template <typename OPTION_ENUM>
    option(OPTION_ENUM name, const sockaddr& value)
        : m_name {static_cast<int>(name)}
        , m_level {detail::option_level<OPTION_ENUM>::value}
        , m_value {value}
    {}

    const int& name() const
    {
        return m_name;
    }

    const int& level() const
    {
        return m_level;
    }

    const sockaddr& value() const
    {
        return m_value;
    }

    sockaddr& value()
    {
        return m_value;
    }

private:
    int m_name;
    int m_level;
    sockaddr m_value;
};

} // namespace net

#endif
