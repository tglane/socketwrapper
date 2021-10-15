#ifndef SOCKETWRAPPER_NET_INTERNAL_BASE_SOCKET_HPP
#define SOCKETWRAPPER_NET_INTERNAL_BASE_SOCKET_HPP

#include "async.hpp"
#include "socket_option.hpp"
#include "utility.hpp"

#include <type_traits>

#include <sys/socket.h>
#include <unistd.h>

namespace net {

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
            detail::async_context::instance().deregister(m_sockfd);
            ::close(m_sockfd);
        }
    }

    template <typename OPTION_ENUM,
        typename OPTION_TYPE,
        typename = std::enable_if_t<std::is_same_v<OPTION_TYPE, int> || std::is_same_v<OPTION_TYPE, timeval> ||
                std::is_same_v<OPTION_TYPE, linger> || std::is_same_v<OPTION_TYPE, sockaddr>,
            bool>>
    void set_option(OPTION_ENUM opt_name, OPTION_TYPE&& opt_val)
    {
        if(::setsockopt(
               m_sockfd, option<OPTION_ENUM>::level, static_cast<int>(opt_name), &opt_val, sizeof(OPTION_TYPE)) != 0)
        {
            throw std::runtime_error {"Failed to set socket option."};
        }
    }

    template <typename OPTION_ENUM,
        typename OPTION_TYPE,
        typename = std::enable_if_t<std::is_same_v<OPTION_TYPE, int> || std::is_same_v<OPTION_TYPE, timeval> ||
                std::is_same_v<OPTION_TYPE, linger> || std::is_same_v<OPTION_TYPE, sockaddr>,
            bool>>
    OPTION_TYPE get_option(socket_option opt_name) const
    {
        OPTION_TYPE opt_val {};
        unsigned int opt_len = sizeof(OPTION_TYPE);
        if(::getsockopt(m_sockfd, option<OPTION_ENUM>::level, static_cast<int>(opt_name), &opt_val, &opt_len) != 0 ||
            opt_len != sizeof(OPTION_TYPE))
        {
            throw std::runtime_error {"Failed to receive socket option."};
        }
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
