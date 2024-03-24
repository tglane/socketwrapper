#ifndef SOCKETWRAPPER_NET_TASK_HPP
#define SOCKETWRAPPER_NET_TASK_HPP

#include <coroutine>
#include <exception>
#include <future>
#include <utility>
#include <variant>

namespace net {

/// General purpose coroutine task that can will execute lazily (you need to await it in order to make the internal
/// coroutine to start executing)
template <typename return_type>
class [[nodiscard]] task
{
public:
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

        task get_return_object()
        {
            // Invoked when we first enter a coroutine. We initialize the precursor handle
            // with a resume point from where the task is ultimately suspended
            return task(std::coroutine_handle<promise_type>::from_promise(*this));
        }

        std::suspend_always initial_suspend() noexcept
        {
            // Initially suspend the task so that it only starts execution when it is awaited
            return {};
        }

        auto final_suspend() noexcept
        {
            return final_awaiter{};
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

    task() = default;

    task(const task&) = delete;
    task& operator=(const task&) = delete;

    task(task&& other)
        : m_handle(std::exchange(other.m_handle, {}))
    {}

    task& operator=(task&& other)
    {
        m_handle = std::exchange(other.m_handle, {});
        return *this;
    }

    ~task()
    {
        if (m_handle)
        {
            m_handle.destroy();
        }
    }

    void resume() const
    {
        m_handle.resume();
    }

    bool await_ready() const noexcept
    {
        // No need to suspend if this task has no outstanding wor
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

    template <typename return_type_t = return_type>
    requires(!std::is_same_v<void, return_type_t>)
    return_type await_resume() const
    {
        // The returned value here is what `co_await our_task` evaluates to
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

    template <typename return_type_t = return_type>
    requires(std::is_same_v<void, return_type_t>)
    void await_resume() const
    {
        auto result = std::exchange(m_handle.promise().m_result, std::monostate());
        if (std::holds_alternative<std::exception_ptr>(result))
        {
            std::rethrow_exception(std::get<std::exception_ptr>(result));
        }
    }

private:
    explicit task(std::coroutine_handle<promise_type> coro)
        : m_handle(coro)
    {}

    std::coroutine_handle<promise_type> m_handle;
};

template <>
struct task<void>::promise_type
{
    // Keep a coroutine handle referring to the parent coroutine if any. That is, if we
    // co_await a coroutine within another coroutine, this handle will be used to continue
    // working from where we left off.
    std::coroutine_handle<> m_continuation;
    std::variant<std::monostate, std::exception_ptr> m_result{std::monostate()};

    promise_type() = default;
    promise_type(const promise_type&) = delete;
    void operator=(const promise_type&) = delete;

    task get_return_object()
    {
        // Invoked when we first enter a coroutine. We initialize the precursor handle
        // with a resume point from where the task is ultimately suspended
        return task{std::coroutine_handle<promise_type>::from_promise(*this)};
    }

    std::suspend_always initial_suspend() noexcept
    {
        return {};
    }

    auto final_suspend() noexcept
    {
        return final_awaiter{};
    }

    void unhandled_exception() noexcept
    {
        // Handle exceptions that were thrown in the coroutines body
        m_result = std::current_exception();
    }

    void return_void() noexcept
    {}
};

} // namespace net

template <typename return_type>
requires(!std::is_void_v<return_type> && !std::is_reference_v<return_type>)
struct std::coroutine_traits<std::future<return_type>, net::task<return_type>>
{
    // Transform a net::task into an eager coroutine that resolves a std::future once it completes
    struct promise_type : std::promise<return_type>
    {
        std::future<return_type> get_return_object() noexcept
        {
            return this->get_future();
        }

        std::suspend_never initial_suspend() const noexcept
        {
            // Starts the execution of the coroutine body right away until it hits a suspension point
            // This makes this an eager evaluated coroutine
            return {};
        }
        std::suspend_never final_suspend() const noexcept
        {
            // Suspend never on final suspend to automatically clean up the coroutine frame when its finished
            return {};
        }

        void return_value(return_type value) noexcept
        {
            // Once the coroutine evaluated to a value we move it into the corresponding future
            this->set_value(std::move(value));
        }

        void unhandled_exception() noexcept
        {
            // Once the coroutine encouters an exception we move it into the corresponding future
            this->set_exception(std::current_exception());
        }
    };
};

template <>
struct std::coroutine_traits<std::future<void>, net::task<void>>
{
    // Transform a net::task into an eager coroutine that resolves a std::future once it completes
    struct promise_type : std::promise<void>
    {
        std::future<void> get_return_object() noexcept
        {
            return this->get_future();
        }

        std::suspend_never initial_suspend() const noexcept
        {
            // Starts the execution of the coroutine body right away until it hits a suspension point
            // This makes this an eager evaluated coroutine
            return {};
        }
        std::suspend_never final_suspend() const noexcept
        {
            // Suspend never on final suspend to automatically clean up the coroutine frame when its finished
            return {};
        }

        void return_void() noexcept
        {
            // Once the coroutine evaluated to a value we move it into the corresponding future
            this->set_value();
        }

        void unhandled_exception() noexcept
        {
            // Once the coroutine encouters an exception we move it into the corresponding future
            this->set_exception(std::current_exception());
        }
    };
};

namespace net {

void async_run();

template <typename return_type>
std::future<return_type> spawn(task<return_type> awaitable_task)
{
    auto task_result = co_await std::move(awaitable_task);
    co_return task_result;
}

template <>
std::future<void> spawn(task<void> awaitable_task)
{
    co_await std::move(awaitable_task);
}

template <typename return_type>
return_type block_on(task<return_type> awaitable_task)
{
    auto task_future = spawn<return_type>(std::move(awaitable_task));
    async_run();
    return task_future.get();
}

} // namespace net

#endif
