#ifndef SOCKETWRAPPER_NET_TIMEOUT_HPP
#define SOCKETWRAPPER_NET_TIMEOUT_HPP

#include <chrono>

#include "detail/event_loop.hpp"

namespace net {

class timeout_t
{
public:
    template <typename duration_unit_t>
    timeout_t(std::chrono::duration<int64_t, duration_unit_t>& time)
    {}
};

template <typename duration_type, typename callback_type>
void async_timeout(duration_type&& timeout, callback_type&& callback)
{}

} // namespace net

#endif
