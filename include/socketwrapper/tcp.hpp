#ifndef SOCKETWRAPPER_NET_TCP_HPP
#define SOCKETWRAPPER_NET_TCP_HPP

#include "span.hpp"
#include "detail/utility.hpp"
#include "detail/async.hpp"
#include "detail/message_notifier.hpp"

#include <string_view>
#include <variant>
#include <optional>
#include <mutex>
#include <condition_variable>
#include <stdexcept>

#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>

namespace net {

template<ip_version IP_VER>
class tcp_connection
{
protected:

    enum class connection_status : uint8_t
    {
        closed,
        connected
    };

public:

    tcp_connection(const tcp_connection&) = delete;
    tcp_connection& operator=(const tcp_connection&) = delete;

    tcp_connection(tcp_connection&& rhs) noexcept
    {
        *this = std::move(rhs);
    }

    tcp_connection& operator=(tcp_connection&& rhs) noexcept
    {
        // Provide custom move assginment operator to prevent the moved socket from closing the underlying file descriptor
        if(this != &rhs)
        {
            m_sockfd = rhs.m_sockfd;
            m_family = rhs.m_family;
            m_peer = std::move(rhs.m_peer);
            m_connection = rhs.m_connection;

            rhs.m_sockfd = -1;
            rhs.m_connection = connection_status::closed;
        }
        return *this;
    }

    tcp_connection(const std::string_view conn_addr, const uint16_t port_to)
        : m_sockfd {::socket(static_cast<uint8_t>(IP_VER), static_cast<uint8_t>(socket_type::stream), 0)}, m_family {IP_VER},
          m_connection {connection_status::closed}
    {
        detail::init_socket_system();

        if(m_sockfd == -1)
            throw std::runtime_error {"Failed to created socket."};

        const int reuse = 1;
        if(::setsockopt(m_sockfd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse)) < 0)
            throw std::runtime_error {"Failed to set address reusable."};

#ifdef SO_REUSEPORT
        if(::setsockopt(m_sockfd, SOL_SOCKET, SO_REUSEPORT, &reuse, sizeof(reuse)) < 0)
            throw std::runtime_error {"Failed to set port reusable."};
#endif

        if(detail::resolve_hostname<IP_VER>(conn_addr, port_to, socket_type::stream, m_peer) != 0)
            throw std::runtime_error {"Failed to resolve hostname."};

        if constexpr(IP_VER == ip_version::v4)
        {
            auto& ref = std::get<sockaddr_in>(m_peer);
            if(auto res = ::connect(m_sockfd, reinterpret_cast<sockaddr*>(&ref), sizeof(sockaddr_in)); res != 0)
                throw std::runtime_error {"Failed to connect."};
            m_connection = connection_status::connected;
        }
        else if constexpr(IP_VER == ip_version::v6)
        {
            auto& ref = std::get<sockaddr_in6>(m_peer);
            if(auto res = ::connect(m_sockfd, reinterpret_cast<sockaddr*>(&ref), sizeof(sockaddr_in)); res != 0)
                throw std::runtime_error {"Failed to connect."};
            m_connection = connection_status::connected;
        }
        else
        {
            static_assert(IP_VER == ip_version::v4 || IP_VER == ip_version::v6);
        }
    }

    ~tcp_connection()
    {
        if(m_connection != connection_status::closed && m_sockfd > 0)
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

    template<typename T>
    size_t send(span<T>&& buffer) const
    {
        if(m_connection == connection_status::closed)
            throw std::runtime_error {"Connection already closed."};

        size_t total = 0;
        const size_t bytes_to_send = buffer.size() * sizeof(T);
        while(total < bytes_to_send)
        {
            switch(const auto bytes = write_to_socket(reinterpret_cast<const char*>(buffer.get()) + total, bytes_to_send - total); bytes)
            {
                case -1:
                    // TODO Check for errors that must be handled
                    throw std::runtime_error {"Failed to read."};
                case 0:
                    m_connection = connection_status::closed;
                    total += bytes;
                    break;
                default:
                    total += bytes;
            }
        }

        return total / sizeof(T);
    }

    template<typename T, typename CALLBACK_TYPE>
    void async_send(span<T>&& buffer, CALLBACK_TYPE&& callback) const
    {
        detail::async_context::instance().add(
            m_sockfd,
            detail::async_context::WRITE,
            [this, buffer = std::move(buffer), func = std::forward<CALLBACK_TYPE>(callback)]() {
                size_t bytes_written = send(std::move(buffer));
                func(bytes_written);
            }
        );
    }

    template<typename T>
    size_t read(span<T>&& buffer) const
    {
        if(m_connection == connection_status::closed)
            throw std::runtime_error {"Connection already closed."};

        switch(const auto bytes = read_from_socket(reinterpret_cast<char*>(buffer.get()), buffer.size() * sizeof(T)); bytes)
        {
            case -1:
                // TODO Maybe handle errno to get some error code?
                throw std::runtime_error {"Failed to read."};
            case 0:
                m_connection = connection_status::closed;
                // fall through
            default:
                return bytes / sizeof(T);
        }
    }

    template<typename T>
    size_t read(span<T>&& buffer, const std::chrono::duration<int64_t, std::milli>& delay) const
    {
        if(m_connection == connection_status::closed)
            throw std::runtime_error {"Connection already closed."};

        auto& notifier = detail::message_notifier::instance();
        std::condition_variable cv;
        std::mutex mut;
        std::unique_lock<std::mutex> lock {mut};
        notifier.add(m_sockfd, &cv);

        // Wait for given delay
        const bool ready = cv.wait_for(lock, delay) == std::cv_status::no_timeout;
        notifier.remove(m_sockfd);

        if(ready)
            return read(span {buffer});
        else
            return 0;
    }

    template<typename T, typename CALLBACK_TYPE>
    void async_read(span<T>&& buffer, CALLBACK_TYPE&& callback) const
    {
        detail::async_context::instance().add(
            m_sockfd,
            detail::async_context::READ,
            [this, buffer = std::move(buffer), func = std::forward<CALLBACK_TYPE>(callback)]()
            {
                // Ok to create new span because its a cheap type containing only a view to the real buffer
                size_t bytes_read = read(span<T> {buffer});
                if(bytes_read == 0)
                    detail::async_context::instance().remove(m_sockfd);
                func(bytes_read);
            }
        );
    }

protected:

    tcp_connection() = default;

    tcp_connection(const int socket_fd, const sockaddr_in& peer_addr)
        : m_sockfd {socket_fd}, m_family {ip_version::v4}, m_peer {peer_addr}, m_connection {connection_status::connected}
    {
        static_assert(IP_VER == ip_version::v4);
    }

    tcp_connection(const int socket_fd, const sockaddr_in6& peer_addr)
        : m_sockfd {socket_fd}, m_family {ip_version::v6}, m_peer {peer_addr}, m_connection {connection_status::connected}
    {
        static_assert(IP_VER == ip_version::v6);
    }

    virtual int read_from_socket(char* const buffer_to, size_t bytes_to_read) const
    {
        return ::recv(m_sockfd, buffer_to, bytes_to_read, 0);
    }

    virtual int write_to_socket(const char* buffer_from, size_t bytes_to_write) const
    {
        return ::send(m_sockfd, buffer_from, bytes_to_write, 0);
    }

    int m_sockfd;

    ip_version m_family;

    std::variant<sockaddr_in, sockaddr_in6> m_peer = {};

    mutable connection_status m_connection;

    template<ip_version>
    friend class tcp_acceptor;

};

/// Using declarations for shorthand usage of templated tcp_connection types
using tcp_connection_v4 = tcp_connection<ip_version::v4>;
using tcp_connection_v6 = tcp_connection<ip_version::v6>;


template<ip_version IP_VER>
class tcp_acceptor
{
public:

    tcp_acceptor() = delete;
    tcp_acceptor(const tcp_acceptor&) = delete;
    tcp_acceptor& operator=(const tcp_acceptor&) = delete;

    tcp_acceptor(tcp_acceptor&& rhs) noexcept
    {
        *this = std::move(rhs);
    }

    tcp_acceptor& operator=(tcp_acceptor&& rhs) noexcept
    {
        // Provide a custom move assginment operator to prevent the moved object from closing the underlying file descriptor
        if(this != &rhs)
        {
            m_sockfd = rhs.m_sockfd;
            m_family = rhs.m_family;
            m_sockaddr = std::move(rhs.m_sockaddr);

            rhs.m_sockfd = -1;
        }
        return *this;
    }

    tcp_acceptor(const std::string_view bind_addr, const uint16_t port, const size_t backlog = 5)
        : m_sockfd {::socket(static_cast<uint8_t>(IP_VER), static_cast<uint8_t>(socket_type::stream), 0)},
          m_family {IP_VER}
    {
        if(m_sockfd == -1)
            throw std::runtime_error {"Failed to create socket."};

        const int reuse = 1;
        if(::setsockopt(m_sockfd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(int)) < 0)
            throw std::runtime_error {"Failed to set address resusable."};

#ifdef SO_REUSEPORT
        if(::setsockopt(m_sockfd, SOL_SOCKET, SO_REUSEPORT, &reuse, sizeof(int)) < 0)
            throw std::runtime_error {"Failed to set port reusable."};
#endif

        if(detail::resolve_hostname<IP_VER>(bind_addr, port, socket_type::stream, m_sockaddr) != 0)
            throw std::runtime_error {"Failed to resolve hostname."};

        if constexpr(IP_VER == ip_version::v4)
        {
            auto& sockaddr_ref = std::get<sockaddr_in>(m_sockaddr);
            if(auto res = ::bind(m_sockfd, reinterpret_cast<sockaddr*>(&sockaddr_ref), sizeof(sockaddr_in)); res != 0)
                throw std::runtime_error {"Failed to bind."};
        }
        else if constexpr(IP_VER == ip_version::v6)
        {
            auto& sockaddr_ref = std::get<sockaddr_in6>(m_sockaddr);
            if(auto res = ::bind(m_sockfd, reinterpret_cast<sockaddr*>(&sockaddr_ref), sizeof(sockaddr_in6)); res != 0)
                throw std::runtime_error {"Failed to bind."};
        }
        else
        {
            static_assert(IP_VER == ip_version::v4 || IP_VER == ip_version::v6);
        }

        if(const auto res = ::listen(m_sockfd, backlog); res != 0)
            throw std::runtime_error {"Failed to initiate listen."};
    }

    ~tcp_acceptor()
    {
        if(m_sockfd > 0)
            ::close(m_sockfd);
    }

    int get() const
    {
        return m_sockfd;
    }

    tcp_connection<IP_VER> accept() const
    {
        if constexpr(IP_VER == ip_version::v4)
        {
            sockaddr_in client {};
            socklen_t len = sizeof(sockaddr_in);
            if(const int sock = ::accept(m_sockfd, reinterpret_cast<sockaddr*>(&client), &len); sock > 0)
                return tcp_connection<IP_VER> {sock, client};
            else
                throw std::runtime_error {"Failed to accept."};
        }
        else if constexpr(IP_VER == ip_version::v6)
        {
            sockaddr_in6 client {};
            socklen_t len = sizeof(sockaddr_in6);
            if(const int sock = ::accept(m_sockfd, reinterpret_cast<sockaddr*>(&client), &len); sock > 0)
                return tcp_connection<IP_VER> {sock, client};
            else
                throw std::runtime_error {"Failed to accept."};
        }
        else
        {
            static_assert(IP_VER == ip_version::v4 || IP_VER == ip_version::v6);
        }
    }

    std::optional<tcp_connection<IP_VER>> accept(const std::chrono::duration<int64_t, std::milli>& delay) const
    {
        auto& notifier = detail::message_notifier::instance();
        std::condition_variable cv;
        std::mutex mut;
        std::unique_lock<std::mutex> lock {mut};
        notifier.add(m_sockfd, &cv);

        // Wait for given delay
        const bool ready = cv.wait_for(lock, delay) == std::cv_status::no_timeout;
        notifier.remove(m_sockfd);

        if(ready)
            return std::optional<tcp_connection<IP_VER>> {accept()};
        else
            return std::nullopt;
    }

    template<typename CALLBACK_TYPE>
    void async_accept(CALLBACK_TYPE&& callback) const
    {
        detail::async_context::instance().add(
            m_sockfd,
            detail::async_context::READ,
            [this, func = std::forward<CALLBACK_TYPE>(callback)]()
            {
                func(accept());
            }
        );
    }

protected:

    int m_sockfd;

    ip_version m_family;

    std::variant<sockaddr_in, sockaddr_in6> m_sockaddr {};

};

/// Using declarations for shorthand usage of templated tcp_acceptor types
using tcp_acceptor_v4 = tcp_acceptor<ip_version::v4>;
using tcp_acceptor_v6 = tcp_acceptor<ip_version::v6>;


} // namespace net

#endif
