#ifndef SOCKETWRAPPER_NET_DETAIL_CALLBACKS_HPP
#define SOCKETWRAPPER_NET_DETAIL_CALLBACKS_HPP

#include "../span.hpp"
#include "./utility.hpp"

#include <memory>
#include <future>
#include <functional>

namespace net {

namespace detail {

/// Forward declarations
class base_socket;

/// Abstract callback type providing a pointer to the socket that issued the callback
//      to "move" active asynchronous operations with a moved socket
struct abstract_socket_callback
{
    abstract_socket_callback(const base_socket* ptr)
        : socket_ptr {ptr}
    {}

    abstract_socket_callback(const abstract_socket_callback&) = delete;
    abstract_socket_callback& operator=(const abstract_socket_callback&) = delete;
    abstract_socket_callback(abstract_socket_callback&&) = default;
    abstract_socket_callback& operator=(abstract_socket_callback&&) = default;

    virtual ~abstract_socket_callback() = default;

    virtual void operator()() const = 0;

    const base_socket* socket_ptr;
};

/// Type erased callback for all asynchronous operations
class async_callback final
{
public:

    template<typename DERIVED_CALLBACK>
    async_callback(DERIVED_CALLBACK&& cb)
        : m_ptr {std::make_unique<DERIVED_CALLBACK>(std::forward<DERIVED_CALLBACK>(cb))}
    {}

    async_callback(const async_callback&) = delete;
    async_callback& operator=(const async_callback&) = delete;
    async_callback(async_callback&&) = default;
    async_callback& operator=(async_callback&&) = default;
    ~async_callback() = default;

    void operator()() const
    {
        (*m_ptr)();
    }

    void reset_socket_ptr(const base_socket* new_ptr)
    {
        m_ptr->socket_ptr = new_ptr;
    }

private:

    std::unique_ptr<abstract_socket_callback> m_ptr;
};

template<typename SOCK_TYPE, typename T>
class stream_read_callback : public detail::abstract_socket_callback
{
public:

    template<typename USER_CALLBACK>
    stream_read_callback(const SOCK_TYPE* sock_ptr, span<T> view, USER_CALLBACK&& cb)
        : detail::abstract_socket_callback {static_cast<const detail::base_socket*>(sock_ptr)},
          m_buffer {std::move(view)},
          m_func {std::forward<USER_CALLBACK>(cb)}
    {}

    void operator()() const override
    {
        const SOCK_TYPE* ptr = static_cast<const SOCK_TYPE*>(this->socket_ptr);
        size_t bytes_read = ptr->read(span<T> {m_buffer.get(), m_buffer.size()});
        m_func(bytes_read);
    }

private:
    span<T> m_buffer;
    std::function<void(size_t)> m_func;
};

template<typename SOCK_TYPE, typename T>
class stream_promised_read_callback : public detail::abstract_socket_callback
{
public:

    stream_promised_read_callback(const SOCK_TYPE* sock_ptr, span<T> view, std::promise<size_t> promise)
        : detail::abstract_socket_callback {static_cast<const detail::base_socket*>(sock_ptr)},
          m_buffer {std::move(view)},
          m_promise {std::move(promise)}
    {}

    void operator()() const override
    {
        const SOCK_TYPE* ptr = static_cast<const SOCK_TYPE*>(this->socket_ptr);
        size_t bytes_read = ptr->read(span<T> {m_buffer.get(), m_buffer.size()});

        m_promise.set_value(bytes_read);
    }

private:
    span<T> m_buffer;
    mutable std::promise<size_t> m_promise;
};

template<typename SOCK_TYPE, typename T>
class stream_write_callback : public detail::abstract_socket_callback
{
public:
    template<typename USER_CALLBACK>
    stream_write_callback(const SOCK_TYPE* sock_ptr, span<T> view, USER_CALLBACK&& cb)
        : detail::abstract_socket_callback {static_cast<const detail::base_socket*>(sock_ptr)},
          m_buffer {std::move(view)},
          m_func {std::forward<USER_CALLBACK>(cb)}
    {}

    void operator()() const override
    {
        const SOCK_TYPE* ptr = static_cast<const SOCK_TYPE*>(this->socket_ptr);
        size_t bytes_written = ptr->send(span<T> {m_buffer.get(), m_buffer.size()});
        m_func(bytes_written);
    }

private:
    span<T> m_buffer;
    std::function<void(size_t)> m_func;
};

template<typename SOCK_TYPE, typename T>
class stream_promised_write_callback : public detail::abstract_socket_callback
{
public:
    stream_promised_write_callback(const SOCK_TYPE* sock_ptr, span<T> view, std::promise<size_t> promise)
        : detail::abstract_socket_callback {static_cast<const detail::base_socket*>(sock_ptr)},
          m_buffer {std::move(view)},
          m_promise {std::move(promise)}
    {}

    void operator()() const override
    {
        const SOCK_TYPE* ptr = static_cast<const SOCK_TYPE*>(this->socket_ptr);
        size_t bytes_written = ptr->send(span<T> {m_buffer.get(), m_buffer.size()});

        m_promise.set_value(bytes_written);
    }

private:
    span<T> m_buffer;
    mutable std::promise<size_t> m_promise;
};

template<typename SOCK_TYPE>
class stream_accept_callback : public detail::abstract_socket_callback
{
    using ACCEPT_SOCK_TYPE = decltype(std::declval<SOCK_TYPE>().accept());
public:

    template<typename USER_CALLBACK>
    stream_accept_callback(const SOCK_TYPE* sock_ptr, USER_CALLBACK&& cb)
        : detail::abstract_socket_callback {sock_ptr},
          m_func {std::forward<USER_CALLBACK>(cb)}
    {}

    void operator()() const override
    {
        const SOCK_TYPE* ptr = static_cast<const SOCK_TYPE*>(this->socket_ptr);
        m_func(ptr->accept());
    }

private:
    std::function<void(ACCEPT_SOCK_TYPE&&)> m_func;
};

template<typename SOCK_TYPE>
class stream_promised_accept_callback : public detail::abstract_socket_callback
{
    using ACCEPT_SOCK_TYPE = decltype(std::declval<SOCK_TYPE>().accept());
public:

    stream_promised_accept_callback(const SOCK_TYPE* sock_ptr, std::promise<ACCEPT_SOCK_TYPE> promise)
        : detail::abstract_socket_callback {sock_ptr},
          m_promise {std::move(promise)}
    {}

    void operator()() const override
    {
        const SOCK_TYPE* ptr = static_cast<const SOCK_TYPE*>(this->socket_ptr);
        m_promise.set_value(ptr->accept());
    }

private:
    mutable std::promise<ACCEPT_SOCK_TYPE> m_promise;
};

template<typename SOCK_TYPE, typename T>
class dgram_read_callback : public detail::abstract_socket_callback
{
    using read_return_pair = std::pair<size_t, connection_info>;

public:

    template<typename USER_CALLBACK>
    dgram_read_callback(const SOCK_TYPE* sock_ptr, span<T> view, USER_CALLBACK&& cb)
        : detail::abstract_socket_callback {sock_ptr},
          m_buffer {std::move(view)},
          m_func {std::forward<USER_CALLBACK>(cb)}
    {}

    void operator()() const override
    {
        const SOCK_TYPE* ptr = static_cast<const SOCK_TYPE*>(this->socket_ptr);
        read_return_pair ret = ptr->read(span {m_buffer.get(), m_buffer.size()});
        m_func(ret.first, std::move(ret.second));
    }

private:
    span<T> m_buffer;
    std::function<void(size_t, connection_info)> m_func;
};

template<typename SOCK_TYPE, typename T>
class dgram_promised_read_callback : public detail::abstract_socket_callback
{
    using read_return_pair = std::pair<size_t, connection_info>;

public:

    dgram_promised_read_callback(const SOCK_TYPE* sock_ptr, span<T> view, std::promise<read_return_pair> promise)
        : detail::abstract_socket_callback {static_cast<const detail::base_socket*>(sock_ptr)},
          m_buffer {std::move(view)},
          m_promise {std::move(promise)}
    {}

    void operator()() const override
    {
        const SOCK_TYPE* ptr = static_cast<const SOCK_TYPE*>(this->socket_ptr);
        read_return_pair ret = ptr->read(span {m_buffer.get(), m_buffer.size()});

        m_promise.set_value(std::move(ret));
    }

private:
    span<T> m_buffer;
    mutable std::promise<read_return_pair> m_promise;
};

template<typename SOCK_TYPE, typename T>
class dgram_write_callback : public detail::abstract_socket_callback
{
public:

    template<typename USER_CALLBACK>
    dgram_write_callback(const SOCK_TYPE* sock_ptr, std::string_view addr, uint16_t port, span<T> view, USER_CALLBACK&& cb)
        : detail::abstract_socket_callback {sock_ptr},
          m_addr {std::move(addr)},
          m_port {port},
          m_buffer {std::move(view)},
          m_func {std::forward<USER_CALLBACK>(cb)}
    {}

    void operator()() const override
    {
        const SOCK_TYPE* ptr = static_cast<const SOCK_TYPE*>(this->socket_ptr);
        size_t bytes_written = ptr->send(m_addr, m_port, span {m_buffer.get(), m_buffer.size()});
        m_func(bytes_written);
    }

private:
    std::string_view m_addr;
    uint16_t m_port;
    span<T> m_buffer;
    std::function<void(size_t)> m_func;
};

template<typename SOCK_TYPE, typename T>
class dgram_promised_write_callback : public detail::abstract_socket_callback
{
public:
    dgram_promised_write_callback(const SOCK_TYPE* sock_ptr, std::string_view addr, uint16_t port, span<T> view, std::promise<size_t> promise)
        : detail::abstract_socket_callback {sock_ptr},
          m_addr {addr},
          m_port {port},
          m_buffer {std::move(view)},
          m_promise {std::move(promise)}
    {}

    void operator()() const override
    {
        const SOCK_TYPE* ptr = static_cast<const SOCK_TYPE*>(this->socket_ptr);
        size_t bytes_written = ptr->send(m_addr, m_port, span {m_buffer.get(), m_buffer.size()});

        m_promise.set_value(bytes_written);
    }

private:
    std::string_view m_addr;
    uint16_t m_port;
    span<T> m_buffer;
    mutable std::promise<size_t> m_promise;
};

} // namespace detail

} // namespace net

#endif
