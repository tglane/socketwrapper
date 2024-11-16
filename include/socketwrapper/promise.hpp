#ifndef SOCKETWRAPPER_NET_PROMISE_HPP
#define SOCKETWRAPPER_NET_PROMISE_HPP

#include <coroutine>
#include <type_traits>

#include "detail/final_awaiter.hpp"
#include "task.hpp"

namespace net {

template <typename return_type>
class [[nodiscard]] promise
{
public:
    struct promise_type
    {
        // Keep a coroutine handle referring to the parent coroutine if any. That is, if we
        // co_await a coroutine within another coroutine, this handle will be used to continue
        // working from where we left off.
        std::coroutine_handle<> m_continuation;

        // Return data
        // std::pair<return_type, std::exception_ptr> m_result;
        std::variant<std::monostate, return_type, std::exception_ptr> m_result{std::monostate()};

        promise_type() = default;
        promise_type(const promise_type&) = delete;
        void operator=(const promise_type&) = delete;

        promise get_return_object()
        {
            // Invoked when we first enter a coroutine. We initialize the precursor handle
            // with a resume point from where the task is ultimately suspended
            return promise(std::coroutine_handle<promise_type>::from_promise(*this));
        }

        std::suspend_never initial_suspend() noexcept
        {
            // We dont want to suspend the promise initially so that it is eagerly evaluated without being awaited
            return {};
        }

        auto final_suspend() noexcept
        {
            return detail::final_awaiter{};
        }

        void unhandled_exception() noexcept
        {
            // Handle exceptions that were thrown in the coroutines body
            m_result = std::current_exception();
        }

        void return_value(return_type value) noexcept
        {
            m_result = std::move(value);
        }
    };

    promise() = default;

    promise(const promise&) = delete;
    promise& operator=(const promise&) = delete;

    promise(promise&& other)
        : m_handle(std::exchange(other.m_handle, {}))
    {}

    promise& operator=(promise&& other)
    {
        m_handle = std::exchange(other.m_handle, {});
        return *this;
    }

    ~promise()
    {
        if (m_handle)
        {
            m_handle.destroy();
        }
    }

    bool done() const
    {
        // Checks, if the coroutine is done executing
        return m_handle.done();
    }

    void resume() const
    {
        // Resumes the coroutine from an external source. This will lead to a cancellatio
        // of any pending awaitable that is currently awaited
        m_handle.resume();
    }

    bool await_ready() const noexcept
    {
        // No need to suspend if this task has no handle assigned and therefore no work to be done
        return !m_handle || m_handle.done();
    }

    auto await_suspend(std::coroutine_handle<> suspended) noexcept
    {
        // The coroutine itself is being suspended (async work can beget other async work)
        // Record the argument as the continuation point when this is resumed later. See
        // the final_suspend awaiter on the promise_type above for where this gets used
        m_handle.promise().m_continuation = suspended;
        return m_handle;
    }

    template <typename return_type_t = return_type, typename = std::enable_if_t<!std::is_same_v<void, return_type_t>>>
    return_type_t await_resume() const
    {
        // The returned value here is what `co_await our_promise` evaluates to
        // return std::move(m_handle.promise().m_result);

        auto result = std::exchange(m_handle.promise().m_result, std::monostate());
        if (std::holds_alternative<return_type>(result))
        {
            return std::move(std::get<return_type>(result));
        }
        else if (std::holds_alternative<std::exception_ptr>(result))
        {
            std::rethrow_exception(std::get<std::exception_ptr>(result));
        }
        else
        {
            // Result is still std::monostate so we never resolved the promise with either a value or an exception
            throw std::runtime_error("Invalid result state");
        }
    }

    template <typename return_type_t, typename = std::enable_if_t<std::is_same_v<void, return_type_t>>>
    void await_resume() const
    {
        auto result = std::exchange(m_handle.promise().m_result, std::monostate());
        if (std::holds_alternative<std::exception_ptr>(result))
        {
            std::rethrow_exception(std::get<std::exception_ptr>(result));
        }
    }

private:
    explicit promise(std::coroutine_handle<promise_type> coro)
        : m_handle(coro)
    {}

    std::coroutine_handle<promise_type> m_handle;
};

template <>
struct promise<void>::promise_type
{
    // Keep a coroutine handle referring to the parent coroutine if any. That is, if we
    // co_await a coroutine within another coroutine, this handle will be used to continue
    // working from where we left off.
    std::coroutine_handle<> m_continuation;
    std::variant<std::monostate, std::exception_ptr> m_result{std::monostate()};

    promise_type() = default;
    promise_type(const promise_type&) = delete;
    void operator=(const promise_type&) = delete;

    promise get_return_object()
    {
        // Invoked when we first enter a coroutine. We initialize the precursor handle
        // with a resume point from where the task is ultimately suspended
        return promise(std::coroutine_handle<promise_type>::from_promise(*this));
    }

    std::suspend_never initial_suspend() noexcept
    {
        return {};
    }

    auto final_suspend() noexcept
    {
        return detail::final_awaiter{};
    }

    void unhandled_exception() noexcept
    {
        // Handle exceptions that were thrown in the coroutines body
        m_result = std::current_exception();
    }

    void return_void() noexcept
    {}
};

void async_run();

// template <typename return_type>
// promise<return_type> spawn(task<return_type> awaitable_task)
// {
//     auto task_result = co_await awaitable_task;
//     co_return task_result;
// }
//
// template <>
// promise<void> spawn(task<void> awaitable_task)
// {
//     co_await awaitable_task;
// }
//
// template <typename return_type>
// return_type block_on(promise<return_type>&& awaitable_promise)
// {
// }

} // namespace net

#endif
