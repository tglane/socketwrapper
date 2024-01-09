#ifndef SOCKETWRAPPER_NET_DETAIL_CALLBACKS_HPP
#define SOCKETWRAPPER_NET_DETAIL_CALLBACKS_HPP

#include "../endpoint.hpp"
#include "../span.hpp"
#include "./utility.hpp"

#include <condition_variable>
#include <functional>
#include <future>

namespace net {

/// Forward declarations
template <ip_version>
class udp_socket;

namespace detail {

/// Forward declarations
class base_socket;

/// Type erased callback for all asynchronous operations
class async_callback
{
public:
    async_callback() = default;
    async_callback(const async_callback&) = delete;
    async_callback& operator=(const async_callback&) = delete;
    async_callback(async_callback&&) = default;
    async_callback& operator=(async_callback&&) = default;
    virtual ~async_callback() = default;

    virtual void invoke() const = 0;

    virtual void reset_socket_ptr(const base_socket*)
    {
        // Blank base implementation because we do not need a socket pointer in every callback type
    }
};

class condition_fullfilled_callback : public async_callback
{
    std::condition_variable* m_cv;

public:
    condition_fullfilled_callback(std::condition_variable& cv)
        : async_callback{}
        , m_cv{&cv}
    {}

    void invoke() const override
    {
        m_cv->notify_one();
    }
};

/// Abstract callback type providing a pointer to the socket that issued the callback
//      to "move" active asynchronous operations with a moved socket
class abstract_socket_callback : public async_callback
{
protected:
    const base_socket* m_socket_ptr;

public:
    abstract_socket_callback(const base_socket* ptr)
        : m_socket_ptr{ptr}
    {}

    abstract_socket_callback(const abstract_socket_callback&) = delete;
    abstract_socket_callback& operator=(const abstract_socket_callback&) = delete;
    abstract_socket_callback(abstract_socket_callback&&) = default;
    abstract_socket_callback& operator=(abstract_socket_callback&&) = default;
    virtual ~abstract_socket_callback() = default;

    void reset_socket_ptr(const base_socket* ptr) override
    {
        m_socket_ptr = ptr;
    }
};

template <typename SOCK_TYPE, typename T>
class stream_read_callback : public detail::abstract_socket_callback
{
public:
    template <typename USER_CALLBACK>
    stream_read_callback(const SOCK_TYPE* sock_ptr, span<T> view, USER_CALLBACK&& cb)
        : detail::abstract_socket_callback{static_cast<const detail::base_socket*>(sock_ptr)}
        , m_buffer{std::move(view)}
        , m_func{std::forward<USER_CALLBACK>(cb)}
    {}

    void invoke() const override
    {
        const SOCK_TYPE* ptr = static_cast<const SOCK_TYPE*>(this->m_socket_ptr);
        size_t bytes_read = ptr->read(m_buffer);
        m_func(bytes_read);
    }

private:
    span<T> m_buffer;
    std::function<void(size_t)> m_func;
};

template <typename SOCK_TYPE, typename T>
class stream_promised_read_callback : public detail::abstract_socket_callback
{
public:
    stream_promised_read_callback(const SOCK_TYPE* sock_ptr, span<T> view, std::promise<size_t> promise)
        : detail::abstract_socket_callback{static_cast<const detail::base_socket*>(sock_ptr)}
        , m_buffer{std::move(view)}
        , m_promise{std::move(promise)}
    {}

    void invoke() const override
    {
        const SOCK_TYPE* ptr = static_cast<const SOCK_TYPE*>(this->m_socket_ptr);
        size_t bytes_read = ptr->read(m_buffer);

        m_promise.set_value(bytes_read);
    }

private:
    span<T> m_buffer;
    mutable std::promise<size_t> m_promise;
};

template <typename SOCK_TYPE, typename T>
class stream_write_callback : public detail::abstract_socket_callback
{
public:
    template <typename USER_CALLBACK>
    stream_write_callback(const SOCK_TYPE* sock_ptr, span<T> view, USER_CALLBACK&& cb)
        : detail::abstract_socket_callback{static_cast<const detail::base_socket*>(sock_ptr)}
        , m_buffer{std::move(view)}
        , m_func{std::forward<USER_CALLBACK>(cb)}
    {}

    void invoke() const override
    {
        const SOCK_TYPE* ptr = static_cast<const SOCK_TYPE*>(this->m_socket_ptr);
        size_t bytes_written = ptr->send(m_buffer);
        m_func(bytes_written);
    }

private:
    span<T> m_buffer;
    std::function<void(size_t)> m_func;
};

template <typename SOCK_TYPE, typename T>
class stream_promised_write_callback : public detail::abstract_socket_callback
{
public:
    stream_promised_write_callback(const SOCK_TYPE* sock_ptr, span<T> view, std::promise<size_t> promise)
        : detail::abstract_socket_callback{static_cast<const detail::base_socket*>(sock_ptr)}
        , m_buffer{std::move(view)}
        , m_promise{std::move(promise)}
    {}

    void invoke() const override
    {
        const SOCK_TYPE* ptr = static_cast<const SOCK_TYPE*>(this->m_socket_ptr);
        size_t bytes_written = ptr->send(m_buffer);

        m_promise.set_value(bytes_written);
    }

private:
    span<T> m_buffer;
    mutable std::promise<size_t> m_promise;
};

template <typename SOCK_TYPE>
class stream_accept_callback : public detail::abstract_socket_callback
{
    using ACCEPT_SOCK_TYPE = decltype(std::declval<SOCK_TYPE>().accept());

public:
    template <typename USER_CALLBACK>
    stream_accept_callback(const SOCK_TYPE* sock_ptr, USER_CALLBACK&& cb)
        : detail::abstract_socket_callback{sock_ptr}
        , m_func{std::forward<USER_CALLBACK>(cb)}
    {}

    void invoke() const override
    {
        const SOCK_TYPE* ptr = static_cast<const SOCK_TYPE*>(this->m_socket_ptr);
        m_func(ptr->accept());
    }

private:
    std::function<void(ACCEPT_SOCK_TYPE&&)> m_func;
};

template <typename SOCK_TYPE>
class stream_promised_accept_callback : public detail::abstract_socket_callback
{
    using ACCEPT_SOCK_TYPE = decltype(std::declval<SOCK_TYPE>().accept());

public:
    stream_promised_accept_callback(const SOCK_TYPE* sock_ptr, std::promise<ACCEPT_SOCK_TYPE> promise)
        : detail::abstract_socket_callback{sock_ptr}
        , m_promise{std::move(promise)}
    {}

    void invoke() const override
    {
        const SOCK_TYPE* ptr = static_cast<const SOCK_TYPE*>(this->m_socket_ptr);
        m_promise.set_value(ptr->accept());
    }

private:
    mutable std::promise<ACCEPT_SOCK_TYPE> m_promise;
};

template <ip_version IP_VER, typename T>
class dgram_read_callback : public detail::abstract_socket_callback
{
    using dgram_operation_res = std::pair<size_t, endpoint<IP_VER>>;

public:
    template <typename USER_CALLBACK>
    dgram_read_callback(const udp_socket<IP_VER>* sock_ptr, span<T> view, USER_CALLBACK&& cb)
        : detail::abstract_socket_callback{sock_ptr}
        , m_buffer{std::move(view)}
        , m_func{std::forward<USER_CALLBACK>(cb)}
    {}

    void invoke() const override
    {
        const udp_socket<IP_VER>* ptr = static_cast<const udp_socket<IP_VER>*>(this->m_socket_ptr);
        dgram_operation_res ret = ptr->read(m_buffer);
        m_func(ret.first, std::move(ret.second));
    }

private:
    span<T> m_buffer;
    std::function<void(size_t, endpoint<IP_VER>)> m_func;
};

template <ip_version IP_VER, typename T>
class dgram_promised_read_callback : public detail::abstract_socket_callback
{
    using dgram_operation_res = std::pair<size_t, endpoint<IP_VER>>;

public:
    dgram_promised_read_callback(const udp_socket<IP_VER>* sock_ptr,
        span<T> view,
        std::promise<dgram_operation_res> promise)
        : detail::abstract_socket_callback{static_cast<const detail::base_socket*>(sock_ptr)}
        , m_buffer{std::move(view)}
        , m_promise{std::move(promise)}
    {}

    void invoke() const override
    {
        const udp_socket<IP_VER>* ptr = static_cast<const udp_socket<IP_VER>*>(this->m_socket_ptr);
        dgram_operation_res ret = ptr->read(m_buffer);

        m_promise.set_value(std::move(ret));
    }

private:
    span<T> m_buffer;
    mutable std::promise<dgram_operation_res> m_promise;
};

template <ip_version IP_VER, typename T>
class dgram_write_callback : public detail::abstract_socket_callback
{
public:
    template <typename USER_CALLBACK>
    dgram_write_callback(const udp_socket<IP_VER>* sock_ptr, endpoint<IP_VER> addr, span<T> view, USER_CALLBACK&& cb)
        : detail::abstract_socket_callback{sock_ptr}
        , m_addr{std::move(addr)}
        , m_buffer{std::move(view)}
        , m_func{std::forward<USER_CALLBACK>(cb)}
    {}

    void invoke() const override
    {
        const udp_socket<IP_VER>* ptr = static_cast<const udp_socket<IP_VER>*>(this->m_socket_ptr);
        size_t bytes_written = ptr->send(m_addr, m_buffer);
        m_func(bytes_written);
    }

private:
    endpoint<IP_VER> m_addr;
    span<T> m_buffer;
    std::function<void(size_t)> m_func;
};

template <ip_version IP_VER, typename T>
class dgram_promised_write_callback : public detail::abstract_socket_callback
{
public:
    dgram_promised_write_callback(const udp_socket<IP_VER>* sock_ptr,
        endpoint<IP_VER> addr,
        span<T> view,
        std::promise<size_t> promise)
        : detail::abstract_socket_callback{sock_ptr}
        , m_addr{std::move(addr)}
        , m_buffer{std::move(view)}
        , m_promise{std::move(promise)}
    {}

    void invoke() const override
    {
        const udp_socket<IP_VER>* ptr = static_cast<const udp_socket<IP_VER>*>(this->m_socket_ptr);
        size_t bytes_written = ptr->send(m_addr, m_buffer);

        m_promise.set_value(bytes_written);
    }

private:
    endpoint<IP_VER> m_addr;
    span<T> m_buffer;
    mutable std::promise<size_t> m_promise;
};

} // namespace detail

} // namespace net

#endif
