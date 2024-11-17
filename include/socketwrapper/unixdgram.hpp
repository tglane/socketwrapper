#ifndef SOCKETWRAPPER_NET_UNIXDGRAM_HPP
#define SOCKETWRAPPER_NET_UNIXDGRAM_HPP

#include "udp.hpp"

namespace net {

using unix_dgram_socket = udp_socket<ip_version::unixsock>;

} // namespace net

#endif
