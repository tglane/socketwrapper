#ifndef SOCKETWRAPPER_NET_SOCKET_OPTION_HPP
#define SOCKETWRAPPER_NET_SOCKET_OPTION_HPP

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
    keep_alive = SO_KEEPALIVE,
    linger = SO_LINGER, // struct linger
    oob_inline = SO_OOBINLINE,
    send_buff_size = SO_SNDBUF,
    recv_buff_size = SO_RCVBUF,
    error = SO_ERROR,
    type = SO_TYPE,
    dont_route = SO_DONTROUTE,
    recv_lowat = SO_RCVLOWAT,
    recv_timeout = SO_RCVTIMEO, // struct timeval
    send_lowat = SO_SNDLOWAT,
    send_timeout = SO_SNDTIMEO // struct timeval
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
    // max_retransmission = TCP_MAXRT,
    max_seg_size = TCP_MAXSEG,
    // keep_alive = TCP_KEEPALIVE
};


enum class option_level : int
{
    socket = SOL_SOCKET,
    tcp = IPPROTO_TCP,
    ipv4 = IPPROTO_IP,
    ipv6 = IPPROTO_IPV6
};

template <option_level, typename T>
class option;

template <option_level LEVEL>
class option<LEVEL, int>
{
public:
    using value_type = int;

    static constexpr const option_level level = LEVEL;

    option(int name)
        : m_name {name}
    {}

    option(int name, int val)
        : m_name {name}
        , m_value {val}
    {}

    const int& name() const
    {
        return m_name;
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
    int m_value;
};

template <option_level LEVEL>
class option<LEVEL, bool>
{
    using value_type = bool;

    static constexpr const option_level level = LEVEL;

    option(int name)
        : m_name {name}
    {}

    option(int name, bool val)
        : m_name {name}
        , m_value {val}
    {}
    const int& name() const
    {
        return m_name;
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
    bool m_value;
};

template <option_level LEVEL>
class option<LEVEL, linger>
{
public:
    using value_type = linger;

    static constexpr const option_level level = LEVEL;

    option(int name)
        : m_name {name}
    {}

    option(int name, const linger& val)
        : m_name {name}
        , m_value {val}
    {}

    const int& name() const
    {
        return m_name;
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
    linger m_value;
};

template <option_level LEVEL>
class option<LEVEL, sockaddr>
{
public:
    using value_type = sockaddr;

    static constexpr const option_level level = LEVEL;

    option(int name)
        : m_name {name}
    {}

    option(int name, const sockaddr& value)
        : m_name {name}
        , m_value {value}
    {}

    const int& name() const
    {
        return m_name;
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
    sockaddr m_value;
};

namespace detail {

template <typename TEST_TYPE, template <auto, typename> class REF_TYPE>
struct is_template_of : std::false_type
{};

template <template <auto, typename> typename REF_TYPE, auto S, typename T>
struct is_template_of<REF_TYPE<S, T>, REF_TYPE> : std::true_type
{};

} // namespace detail

} // namespace net

#endif
