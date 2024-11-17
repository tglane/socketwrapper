#ifndef SOCKETWRAPPER_NET_UNIXSTREAM_HPP
#define SOCKETWRAPPER_NET_UNIXSTREAM_HPP

#include "tcp.hpp"

namespace net {

using unix_stream_connection = tcp_connection<ip_version::unixsock>;
using unix_stream_acceptor = tcp_acceptor<ip_version::unixsock>;

} // namespace net

#endif
