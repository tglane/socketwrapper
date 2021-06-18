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
constexpr inline T to_big_endian(T little)
{
    return detail::swap_byteorder<T>(little);
}

template<typename T>
constexpr inline T to_little_endian(T big)
{
    return detail::swap_byteorder<T>(big);
}

/// Free function to easily wait until the async_context runs out of registered events
inline void async_run()
{
    detail::async_context::instance().run();
}

} // namespace net

#endif
