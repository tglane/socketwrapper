#ifndef SOCKETWRAPPER_NET_INTERNAL_BASE_SOCKET_HPP
#define SOCKETWRAPPER_NET_INTERNAL_BASE_SOCKET_HPP

#include <type_traits>

#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>

#include "event_loop.hpp"
#include "socket_option.hpp"
#include "utility.hpp"

namespace net {

namespace detail {

/// Socket base class
class base_socket
{
protected:
    int m_sockfd;

    ip_version m_family;

    base_socket(int sockfd, ip_version ip_ver)
        : m_sockfd{sockfd}
        , m_family{ip_ver}
    {
        if (m_sockfd == -1)
        {
            throw std::runtime_error{"Failed to create socket."};
        }

        const int reuse = 1;
        if (::setsockopt(m_sockfd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse)) < 0)
        {
            throw std::runtime_error{"Failed to set address reusable."};
        }

#ifdef SO_REUSEPORT
        if (::setsockopt(m_sockfd, SOL_SOCKET, SO_REUSEPORT, &reuse, sizeof(reuse)) < 0)
        {
            throw std::runtime_error{"Failed to set port reusable."};
        }
#endif
    }

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
        if (this != &rhs)
        {
            m_sockfd = rhs.m_sockfd;
            m_family = rhs.m_family;

            rhs.m_sockfd = -1;
        }
        return *this;
    }

    base_socket(socket_type type, ip_version ip_ver)
        : m_sockfd{::socket(static_cast<uint8_t>(ip_ver), static_cast<uint8_t>(type), 0)}
        , m_family{ip_ver}
    {
        detail::init_socket_system();

        if (m_sockfd == -1)
        {
            throw std::runtime_error{"Failed to create socket."};
        }

        set_option(option<option_level::socket, SO_REUSEADDR, int>{1});
#ifdef SO_REUSEPORT
        set_option(option<option_level::socket, SO_REUSEPORT, int>{1});
#endif
    }

    virtual ~base_socket()
    {
        if (m_sockfd > 0)
        {
            auto& exec = event_loop::instance();
            exec.deregister(m_sockfd);
            ::close(m_sockfd);
        }
    }

    template <typename OPTION_TYPE,
        typename = std::enable_if_t<detail::is_template_of<OPTION_TYPE, option>::value, bool>>
    void set_option(OPTION_TYPE&& opt_val)
    {
        if (::setsockopt(m_sockfd,
                opt_val.level_native(),
                opt_val.name(),
                reinterpret_cast<const char*>(opt_val.value()),
                opt_val.size()) != 0)
        {
            throw std::runtime_error{"Failed to set socket option."};
        }
    }

    template <typename OPTION_TYPE,
        typename = std::enable_if_t<detail::is_template_of<OPTION_TYPE, option>::value, bool>>
    OPTION_TYPE get_option() const
    {
        OPTION_TYPE opt_val{};
        unsigned int opt_len = opt_val.size();
        if (::getsockopt(
                m_sockfd, opt_val.level_native(), opt_val.name(), reinterpret_cast<char*>(opt_val.value()), &opt_len) !=
            0)
        {
            throw std::runtime_error{"Failed to get socket option."};
        }
        return opt_val;
    }

    template <typename OPTION_TYPE,
        typename = std::enable_if_t<detail::is_template_of<OPTION_TYPE, option>::value, bool>>
    typename OPTION_TYPE::value_type get_option_value() const
    {
        return *get_option<OPTION_TYPE>().value();
    }

    size_t bytes_available() const
    {
        size_t bytes = 0;
        ::ioctl(m_sockfd, FIONREAD, &bytes);
        return bytes;
    }

    void cancel() const
    {
        // Cancel all pending async operations
        auto& exec = detail::event_loop::instance();
        exec.deregister(m_sockfd);
    }

    int get() const
    {
        return m_sockfd;
    }

    ip_version family() const
    {
        return m_family;
    }
};

} // namespace detail

} // namespace net

#endif
