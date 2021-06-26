#ifndef SOCKETWRAPPER_NET_DETAIL_CALLBACKS_HPP
#define SOCKETWRAPPER_NET_DETAIL_CALLBACKS_HPP

#include <memory>

namespace net {

namespace detail {

/// Forward declarations
class base_socket;

/// Abstract callback type providing a pointer to the socket that issued the callback
//      to "move" active asynchronous operations with a moved socket
struct abstract_socket_callback
{
    virtual ~abstract_socket_callback()
    {}

    virtual void operator()() const = 0;

    const base_socket* socket_ptr;
};

/// Type erased callback for all asynchronous operations
class async_callback final
{
public:

    template<typename USER_CALLBACK>
    async_callback(USER_CALLBACK&& cb)
        : m_ptr {std::make_unique<USER_CALLBACK>(std::forward<USER_CALLBACK>(cb))}
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


} // namespace detail

} // namespace net

#endif
