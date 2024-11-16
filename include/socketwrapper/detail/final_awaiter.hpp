#ifndef SOCKETWRAPPER_NET_DETAIL_FINAL_AWAITER_HPP
#define SOCKETWRAPPER_NET_DETAIL_FINAL_AWAITER_HPP

#include <coroutine>

namespace net {

namespace detail {

struct final_awaiter
{
    // The coroutine is about to complete (via co_return or reaching the end of the coroutine body).
    // The awaiter returned here defines what happens next

    bool await_ready() const noexcept
    {
        return false;
    }

    template <typename promise>
    std::coroutine_handle<> await_suspend(std::coroutine_handle<promise> suspended) noexcept
    {
        // final_awaiter::await_suspend is called when the execution of the
        // current coroutine (suspended) is about to finish.
        // If the current coroutine was resumed by another coroutine via
        // co_await, a handle to that coroutine has been stored
        // as suspended.promise().continuation. In that case, return the handle to resume
        // the previous coroutine.
        // Otherwise, return noop_coroutine(), whose resumption does nothing.
        if (suspended.promise().m_continuation)
        {
            return suspended.promise().m_continuation;
        }
        else
        {
            return std::noop_coroutine();
        }
    }

    void await_resume() const noexcept
    {}
};

} // namespace detail

} // namespace net

#endif
