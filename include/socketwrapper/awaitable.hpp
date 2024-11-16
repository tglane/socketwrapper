#ifndef SOCKETWRAPPER_NET_AWAITABLE_HPP
#define SOCKETWRAPPER_NET_AWAITABLE_HPP

#include <coroutine>
// #include <cstddef>
#include <type_traits>

#include <sys/ioctl.h>

#include "detail/event_loop.hpp"

namespace net {

/// Awaitable type for all network related I/O operations of this library
template <typename return_type, typename operation_type>
class op_awaitable
{
    operation_type m_operation;
    detail::event_type m_event;
    int m_fd;

public:
    using value_type = return_type;

    op_awaitable(int fd, operation_type op, detail::event_type event)
        : m_operation(std::move(op))
        , m_event{event}
        , m_fd(fd)
    {}

    ~op_awaitable()
    {
        // If we have not received an result at this point we need to remove the event/fd combo from the event loop
        // This could happen if this awaitable is invoked in the net::select(...) function which will drop all
        // awaitables except for the one that finishes first
        auto& exec = detail::event_loop::instance();
        exec.remove(m_fd, m_event);
    }

    bool await_ready() noexcept
    {
        // Return false to suspend the coroutine initially
        // Returning true would mean that we directly call await_resume without calling await_suspend first to
        // start the async io operation

        // TODO Make the operation return would_block | result

        return false;
    }

    void await_suspend(std::coroutine_handle<> suspended) noexcept
    {
        // Create a coroutine resumption task that gets executed from the event_loop when the event appears
        auto& exec = detail::event_loop::instance();
        exec.spawn(m_fd, m_event, detail::coroutine_completion_handler(suspended));
    }

    template <typename return_type_t = return_type, typename = std::enable_if_t<std::is_same_v<return_type_t, void>>>
    void await_resume()
    {
        m_operation();
    }

    template <typename return_type_t = return_type, typename = std::enable_if_t<!std::is_same_v<return_type_t, void>>>
    return_type_t await_resume()
    {
        auto op_result = m_operation();
        return std::move(op_result);
    }
};

} // namespace net

#endif
