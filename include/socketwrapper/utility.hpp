#ifndef SOCKETWRAPPER_NET_UTILITY_HPP
#define SOCKETWRAPPER_NET_UTILITY_HPP

#include "detail/utility.hpp"
#include "detail/async.hpp"

#include <string>
#include <cstdint>

#include <netdb.h>

namespace net {

/// Change endianess
template<typename T>
T (*to_big_endian)(T) = detail::swap_byteorder<T>;

template<typename T>
T (*to_little_endian)(T) = detail::swap_byteorder<T>;

/// Free function to easily wait until the async_context runs out of registered events
inline void async_run()
{
    detail::async_context::instance().run();
}

} // namespace net

#endif
