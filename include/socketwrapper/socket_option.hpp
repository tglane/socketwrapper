#ifndef SOCKETWRAPPER_NET_SOCKET_OPTION_HPP
#define SOCKETWRAPPER_NET_SOCKET_OPTION_HPP

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
{};

enum class ipv6_option : int
{};

enum class tcp_option : int
{
    // max_retransmission = TCP_MAXRT,
    max_seg_size = TCP_MAXSEG,
    // keep_alive = TCP_KEEPALIVE
};

namespace detail {

template <typename OPTION_TYPE>
struct option;

template <>
struct option<socket_option>
{
    static constexpr const int level = SOL_SOCKET;
};

template <>
struct option<ipv4_option>
{
    static constexpr const int level = IPPROTO_IP;
};

template <>
struct option<ipv6_option>
{
    static constexpr const int level = IPPROTO_IPV6;
};

template <>
struct option<tcp_option>
{
    static constexpr const int level = IPPROTO_TCP;
};

} // namespace detail

} // namespace net

#endif
