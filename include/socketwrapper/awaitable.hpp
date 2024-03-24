#ifndef SOCKETWRAPPER_NET_AWAITABLE_HPP
#define SOCKETWRAPPER_NET_AWAITABLE_HPP

#include <coroutine>
#include <cstddef>

#include <sys/ioctl.h>

#include "detail/event_loop.hpp"

namespace net {

/// Awaitable type for all network related I/O operations of this library
template <typename result_type, typename operation_type>
class op_awaitable
{
    operation_type m_operation;
    detail::event_type m_event;
    int m_fd;

public:
    using operation = operation_type;

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
        if (m_fd > 0)
        {
            auto& exec = detail::event_loop::instance();
            exec.remove(m_fd, m_event);
        }
    }

    bool await_ready() noexcept
    {
        // Return false to suspend the coroutine initially
        // Returning true would mean that we directly call await_resume without calling await_suspend first to
        // start the async io operation
        size_t bytes_available = 0;
        ::ioctl(m_fd, FIONREAD, &bytes_available);
        return bytes_available > 0;
    }

    void await_suspend(std::coroutine_handle<> suspended) noexcept
    {
        // Create a coroutine resumption task that gets executed from the event_loop when the event appears
        auto& exec = detail::event_loop::instance();
        exec.add(m_fd, m_event, detail::coroutine_completion_handler(suspended));
    }

    result_type await_resume()
    {
        auto op_result = m_operation(m_fd);
        m_fd = -1;
        return std::move(op_result);
    }
};

} // namespace net

#endif
