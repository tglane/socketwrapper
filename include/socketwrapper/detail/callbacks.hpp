#ifndef SOCKETWRAPPER_NET_DETAIL_CALLBACKS_HPP
#define SOCKETWRAPPER_NET_DETAIL_CALLBACKS_HPP

#include <exception>
#include <functional>
#include <future>

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
    template <typename INVOKE_FUNC>
    no_return_completion_handler(INVOKE_FUNC&& operation)
        : completion_handler()
        , m_operation(std::forward<INVOKE_FUNC>(operation))
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

template <typename RET>
class promise_completion_handler : public completion_handler
{
    std::function<RET(const int)> m_operation;
    std::promise<RET> m_fullfill;

public:
    template <typename INVOKE_FUNC>
    promise_completion_handler(INVOKE_FUNC&& operation, std::promise<RET> fullfill)
        : completion_handler()
        , m_operation(std::forward<INVOKE_FUNC>(operation))
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

template <typename RET>
class callback_completion_handler : public completion_handler
{
    std::function<RET(const int)> m_operation;
    std::function<void(RET, std::exception_ptr)> m_fullfill;

public:
    template <typename INVOKE_FUNC, typename CALLBACK_FUNC>
    callback_completion_handler(INVOKE_FUNC&& operation, CALLBACK_FUNC&& callback)
        : completion_handler()
        , m_operation(std::forward<INVOKE_FUNC>(operation))
        , m_fullfill(std::forward<CALLBACK_FUNC>(callback))
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

} // namespace detail

} // namespace net

#endif
