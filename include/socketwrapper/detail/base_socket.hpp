#ifndef SOCKETWRAPPER_NET_INTERNAL_BASE_SOCKET_HPP
#define SOCKETWRAPPER_NET_INTERNAL_BASE_SOCKET_HPP

#include "async.hpp"
#include "utility.hpp"

#include "unistd.h"

namespace net {

enum class socket_option : int
{
    debug = SO_DEBUG,
    accept_conn = SO_ACCEPTCONN,
    broadcast = SO_BROADCAST,
    reuse_addr = SO_REUSEADDR,
    keep_alive = SO_KEEPALIVE,
    linger = SO_LINGER, // struct linger
    oob_inline = SO_OOBINLINE,
    send_buff = SO_SNDBUF,
    recv_buff = SO_RCVBUF,
    error = SO_ERROR,
    type = SO_TYPE,
    dont_route = SO_DONTROUTE,
    recv_lowat = SO_RCVLOWAT,
    recv_timeout = SO_RCVTIMEO, // struct timeval
    send_lowat = SO_SNDLOWAT,
    send_timeout = SO_SNDTIMEO // struct timeval
};

namespace detail {

/// Very simple socket base class
class base_socket
{
public:
    base_socket(const base_socket&) = delete;
    base_socket& operator=(const base_socket&) = delete;

    base_socket(base_socket&& rhs) noexcept
    {
        *this = std::move(rhs);
    }

    base_socket& operator=(base_socket&& rhs) noexcept
    {
        // Provide custom move assginment operator to prevent the moved socket from closing the underlying file
        // descriptor
        if(this != &rhs)
        {
            m_sockfd = rhs.m_sockfd;
            m_family = rhs.m_family;

            async_context::instance().callback_update_socket(m_sockfd, this);

            rhs.m_sockfd = -1;
        }
        return *this;
    }

    base_socket(socket_type type, ip_version ip_ver)
        : m_sockfd {::socket(static_cast<uint8_t>(ip_ver), static_cast<uint8_t>(type), 0)}
        , m_family {ip_ver}
    {
        detail::init_socket_system();

        if(m_sockfd == -1)
            throw std::runtime_error {"Failed to create socket."};

        const int reuse = 1;
        if(::setsockopt(m_sockfd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse)) < 0)
            throw std::runtime_error {"Failed to set address reusable."};

#ifdef SO_REUSEPORT
        if(::setsockopt(m_sockfd, SOL_SOCKET, SO_REUSEPORT, &reuse, sizeof(reuse)) < 0)
            throw std::runtime_error {"Failed to set port reusable."};
#endif
    }

    virtual ~base_socket()
    {
        if(m_sockfd > 0)
        {
            // TODO only do this when the socket is still in the async context
            detail::async_context::instance().deregister(m_sockfd);
            ::close(m_sockfd);
        }
    }

    template <typename OPTION_TYPE>
    void set_option(socket_option opt_name, OPTION_TYPE&& opt_val)
    {
        // if(::setsockopt(m_sockfd, SOL_SOCKET, static_cast<int>(opt_name), &opt_val, sizeof(OPTION_TYPE)) != 0)
        if(::setsockopt(m_sockfd, SOL_SOCKET, static_cast<int>(opt_name), &opt_val, sizeof(OPTION_TYPE)) != 0)
            throw std::runtime_error {"Failed to set socket option."};
    }

    template <socket_option OPT_NAME>
    void set_option(const std::variant<int, timeval, linger>& opt_val)
    {
        if constexpr(OPT_NAME == socket_option::linger)
        {
            const linger& casted_val = std::get<linger>(opt_val);
            ::setsockopt(m_sockfd, SOL_SOCKET, static_cast<int>(OPT_NAME), &casted_val, sizeof(linger));
        }
        else if constexpr(OPT_NAME == socket_option::recv_timeout || OPT_NAME == socket_option::send_timeout)
        {
            const timeval& casted_val = std::get<timeval>(opt_val);
            ::setsockopt(m_sockfd, SOL_SOCKET, static_cast<int>(OPT_NAME), &casted_val, sizeof(timeval));
        }
        else
        {
            const int& casted_val = std::get<int>(opt_val);
            ::setsockopt(m_sockfd, SOL_SOCKET, static_cast<int>(OPT_NAME), &casted_val, sizeof(int));
        }
    }

    template <typename OPTION_TYPE>
    OPTION_TYPE get_option(socket_option opt_name) const
    {
        OPTION_TYPE opt_val {};
        size_t opt_len {};
        if(::getsockopt(m_sockfd, SOL_SOCKET, static_cast<int>(opt_name), &opt_val, &opt_len) != 0 ||
            opt_len != sizeof(OPTION_TYPE))
            throw std::runtime_error {"Failed to receive socket option."};
        return opt_val;
    }

    int get() const
    {
        return m_sockfd;
    }

    ip_version family() const
    {
        return m_family;
    }

protected:
    base_socket(int sockfd, ip_version ip_ver)
        : m_sockfd {sockfd}
        , m_family {ip_ver}
    {
        if(m_sockfd == -1)
            throw std::runtime_error {"Failed to create socket."};

        const int reuse = 1;
        if(::setsockopt(m_sockfd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse)) < 0)
            throw std::runtime_error {"Failed to set address reusable."};

#ifdef SO_REUSEPORT
        if(::setsockopt(m_sockfd, SOL_SOCKET, SO_REUSEPORT, &reuse, sizeof(reuse)) < 0)
            throw std::runtime_error {"Failed to set port reusable."};
#endif
    }

    int m_sockfd;

    ip_version m_family;
};

} // namespace detail

} // namespace net

#endif
