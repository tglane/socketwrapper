#ifndef SOCKETWRAPPER_NET_DETAIL_CALLBACKS_HPP
#define SOCKETWRAPPER_NET_DETAIL_CALLBACKS_HPP

#include <exception>
#include <functional>
#include <future>

#if __cplusplus >= 202002L
#include <coroutine>
#endif

namespace net {

namespace detail {

class completion_handler
{
public:
    virtual ~completion_handler()
    {}

    virtual void invoke(const int) = 0;
};

class no_return_completion_handler : public completion_handler
{
    std::function<void(const int)> m_operation;

public:
    template <typename invoke_type>
    no_return_completion_handler(invoke_type&& operation)
        : completion_handler()
        , m_operation(std::forward<invoke_type>(operation))
    {}

    void invoke(const int fd) override
    {
        try
        {
            m_operation(fd);
        }
        catch (...)
        {
            // Here the exception wont get handled since there is no result handler
        }
    }
};

template <typename return_type>
class promise_completion_handler : public completion_handler
{
    std::function<return_type(const int)> m_operation;
    std::promise<return_type> m_fullfill;

public:
    template <typename invoke_type>
    promise_completion_handler(invoke_type&& operation, std::promise<return_type> fullfill)
        : completion_handler()
        , m_operation(std::forward<invoke_type>(operation))
        , m_fullfill(std::move(fullfill))
    {}

    void invoke(const int fd) override
    {
        try
        {
            auto result = m_operation(fd);
            m_fullfill.set_value(std::move(result));
        }
        catch (...)
        {
            m_fullfill.set_exception(std::current_exception());
        }
    }
};

template <typename return_type>
class callback_completion_handler : public completion_handler
{
    std::function<return_type(const int)> m_operation;
    std::function<void(return_type, std::exception_ptr)> m_fullfill;

public:
    template <typename invoke_type, typename callback_type>
    callback_completion_handler(invoke_type&& operation, callback_type&& callback)
        : completion_handler()
        , m_operation(std::forward<invoke_type>(operation))
        , m_fullfill(std::forward<callback_type>(callback))
    {}

    void invoke(const int fd) override
    {
        try
        {
            auto result = m_operation(fd);
            m_fullfill(std::move(result), nullptr);
        }
        catch (...)
        {
            m_fullfill({}, std::current_exception());
        }
    };
};

#if __cplusplus >= 202002L
class coroutine_completion_handler : public completion_handler
{
    std::coroutine_handle<> m_waiting_coroutine;

public:
    coroutine_completion_handler(std::coroutine_handle<> suspended)
        : completion_handler()
        , m_waiting_coroutine(suspended)
    {}

    void invoke(const int) override
    {
        // For coroutines we only need the coroutine handle from the op_awaitable to be resumed
        // The operation is than executed by the op_awaitable that spawned the async task on executor
        m_waiting_coroutine.resume();
    };
};
#endif

} // namespace detail

} // namespace net

#endif
