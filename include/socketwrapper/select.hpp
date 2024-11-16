#ifndef SOCKETWRAPPER_NET_SELECT_HPP
#define SOCKETWRAPPER_NET_SELECT_HPP

#include <coroutine>
#include <tuple>

namespace net {

namespace detail {

struct selectable_task
{
    struct promise_type
    {
        std::suspend_never initial_suspend() noexcept
        {
            return {};
        }

        auto final_suspend() noexcept
        {
            class completion_notifier
            {
            public:
                bool await_ready() const noexcept
                {
                    return false;
                }

                void await_suspend(std::coroutine_handle<selectable_task>) const noexcept
                {
                    // TODO Notify somehow
                    // coro.promise().m_counter->notify_awaitable_completed();
                }

                void await_resume() const noexcept
                {}
            };
            return completion_notifier{};
        }

        auto get_return_object()
        {
            return std::coroutine_handle<promise_type>::from_promise(*this);
        }

        void unhandled_exception()
        {}

        void return_void()
        {}
    };

    selectable_task(std::coroutine_handle<promise_type> suspended)
        : m_handle(suspended)
    {}

    void start_awaiting()
    {}

private:
    std::coroutine_handle<promise_type> m_handle;
};

template <typename awaitable_t>
selectable_task make_selectable_task(awaitable_t&& awaitable)
{
    co_yield co_await std::move(awaitable);
}

template <typename... task_t>
struct select_awaitable
{
    select_awaitable(std::tuple<task_t...> awaitables)
        : m_awaitables(std::move(awaitables))
    {}

    bool await_ready() const noexcept
    {
        return false;
    }

    void await_suspend(std::coroutine_handle<>) noexcept
    {
        // TODO
        std::apply([](auto&&... as) { (as.start_awaiting(), ...); }, m_awaitables);
    }

    void await_resume() noexcept
    {}

private:
    std::tuple<task_t...> m_awaitables;
};

} // namespace detail

template <typename... awaitable_t>
detail::select_awaitable<awaitable_t...> select(awaitable_t&&... awaitables)
{
    return detail::select_awaitable<awaitable_t...>(
        std::make_tuple(detail::make_selectable_task(std::forward<awaitable_t>(awaitables))...));
}

} // namespace net

#endif
