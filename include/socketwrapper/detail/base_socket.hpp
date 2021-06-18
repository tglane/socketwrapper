#ifndef SOCKETWRAPPER_NET_INTERNAL_BASE_SOCKET_HPP
#define SOCKETWRAPPER_NET_INTERNAL_BASE_SOCKET_HPP

#include "utility.hpp"
#include "async.hpp"
#include <iostream>

#include "unistd.h"

namespace net {

namespace detail {

/// Very simple socket base class
template<ip_version IP_VER>
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
        // Provide custom move assginment operator to prevent the moved socket from closing the underlying file descriptor
        if(this != &rhs)
        {
            m_sockfd = rhs.m_sockfd;
            m_family = rhs.m_family;

            rhs.m_sockfd = -1;
        }
        return *this;
    }

    base_socket(socket_type type)
        : m_sockfd {::socket(static_cast<uint8_t>(IP_VER), static_cast<uint8_t>(type), 0)},
          m_family {IP_VER}
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

    ~base_socket()
    {
        if(m_sockfd > 0)
        {
            // TODO only do this when the socket is still in the async context
            detail::async_context::instance().remove(m_sockfd);
            ::close(m_sockfd);
        }
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
        : m_sockfd {sockfd},
          m_family {ip_ver}
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