#ifndef SOCKETWRAPPER_NET_TCP_HPP
#define SOCKETWRAPPER_NET_TCP_HPP

#include <condition_variable>
#include <future>
#include <mutex>
#include <optional>
#include <stdexcept>

#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include "detail/base_socket.hpp"
#include "detail/event_loop.hpp"
#include "detail/utility.hpp"
#include "endpoint.hpp"
#include "span.hpp"
#if __cplusplus >= 202002L
#include "awaitable.hpp"
#endif

namespace net {

template <ip_version ip_ver_v>
class tcp_connection : public detail::base_socket
{
protected:
    enum class connection_status : uint8_t
    {
        closed,
        connected
    };

    template <typename data_type>
    struct stream_write_operation
    {
        span<data_type> m_buffer_to;

        stream_write_operation(span<data_type> buffer)
            : m_buffer_to(buffer)
        {}

        size_t operator()(const int fd) const
        {
            size_t total = 0;
            const size_t bytes_to_send = m_buffer_to.size() * sizeof(data_type);
            while (total < bytes_to_send)
            {
                switch (const auto bytes = ::send(fd,
                            reinterpret_cast<const char*>(m_buffer_to.get()) + total,
                            m_buffer_to.size() * sizeof(data_type),
                            0);
                        bytes)
                {
                    case -1:
                        throw std::runtime_error{"Failed to write."};
                    case 0:
                        total += bytes;
                        break;
                    default:
                        total += bytes;
                }
            }
            return total / sizeof(data_type);
        }
    };

    template <typename data_type>
    struct stream_read_operation
    {
        span<data_type> m_buffer_from;

        stream_read_operation(span<data_type> buffer)
            : m_buffer_from(buffer)
        {}

        size_t operator()(const int fd)
        {
            switch (const auto bytes = ::recv(
                        fd, reinterpret_cast<char*>(m_buffer_from.get()), m_buffer_from.size() * sizeof(data_type), 0);
                    bytes)
            {
                case -1:
                    throw std::runtime_error{"Failed to read."};
                case 0:
                    // fall through
                default:
                    return bytes / sizeof(data_type);
            }
        }
    };

    std::optional<endpoint<ip_ver_v>> m_peer;

    mutable connection_status m_connection;

    tcp_connection(const int socket_fd, const endpoint<ip_ver_v>& peer_addr)
        : detail::base_socket{socket_fd, ip_ver_v}
        , m_peer{peer_addr}
        , m_connection{connection_status::connected}
    {}

    template <ip_version>
    friend class tcp_acceptor;

public:
    tcp_connection()
        : detail::base_socket{socket_type::stream, ip_ver_v}
        , m_peer{std::nullopt}
        , m_connection{connection_status::closed}
    {}

    tcp_connection(const tcp_connection&) = delete;
    tcp_connection& operator=(const tcp_connection&) = delete;

    tcp_connection(tcp_connection&& rhs) noexcept
        : detail::base_socket{std::move(rhs)}
    {
        m_peer = std::move(rhs.m_peer);
        m_connection = rhs.m_connection;

        rhs.m_connection = connection_status::closed;
    }

    tcp_connection& operator=(tcp_connection&& rhs) noexcept
    {
        // Provide custom move assginment operator to prevent the moved socket from closing the underlying file
        // descriptor
        if (this != &rhs)
        {
            detail::base_socket::operator=(std::move(rhs));

            m_peer = std::move(rhs.m_peer);
            m_connection = rhs.m_connection;

            rhs.m_connection = connection_status::closed;
        }
        return *this;
    }

    tcp_connection(const endpoint<ip_ver_v>& conn_addr)
        : detail::base_socket{socket_type::stream, ip_ver_v}
        , m_connection{connection_status::closed}
    {
        connect(conn_addr);
    }

    virtual void connect(const endpoint<ip_ver_v>& conn_addr)
    {
        if (m_connection != connection_status::closed)
        {
            return;
        }

        m_peer = conn_addr;
        if (const auto res = ::connect(m_sockfd, &(m_peer->get_addr()), m_peer->addr_size); res != 0)
        {
            throw std::runtime_error{"Failed to connect."};
        }

        m_connection = connection_status::connected;
    }

    template <typename data_type>
    size_t send(span<data_type> buffer) const
    {
        if (m_connection == connection_status::closed)
        {
            throw std::runtime_error{"Connection already closed."};
        }

        auto write_op = stream_write_operation<data_type>(buffer);
        return write_op(m_sockfd);
    }

    template <typename data_type>
    std::optional<size_t> send(span<data_type> buffer, const std::chrono::duration<int64_t, std::milli>& timeout) const
    {
        if (m_connection == connection_status::closed)
        {
            throw std::runtime_error{"Connection already closed."};
        }

        auto mut = std::mutex();
        auto cv = std::condition_variable();
        auto lock = std::unique_lock<std::mutex>{mut};

        auto& exec = detail::event_loop::instance();
        exec.add(
            m_sockfd, detail::event_type::WRITE, detail::no_return_completion_handler([&cv](int) { cv.notify_one(); }));

        // Wait for given timeout
        const auto condition_status = cv.wait_for(lock, timeout);
        if (condition_status == std::cv_status::no_timeout)
        {
            return send(buffer);
        }
        else
        {
            exec.remove(m_sockfd, detail::event_type::WRITE);
            return std::nullopt;
        }
    }

    template <typename data_type, typename callback_type>
    void async_send(span<data_type> buffer, callback_type&& callback) const
    {
        auto& exec = detail::event_loop::instance();
        exec.add(m_sockfd,
            detail::event_type::WRITE,
            detail::callback_completion_handler<size_t>(
                stream_write_operation<data_type>(buffer), std::forward<callback_type>(callback)));
    }

#if __cplusplus >= 202002L
    template <typename data_type>
    op_awaitable<size_t, stream_write_operation<data_type>> async_send(span<data_type> buffer) const
    {
        return op_awaitable<size_t, stream_write_operation<data_type>>(
            m_sockfd, stream_write_operation<data_type>(buffer), detail::event_type::WRITE);
    }
#endif

    template <typename data_type>
    std::future<size_t> promised_send(span<data_type> buffer) const
    {
        auto size_promise = std::promise<size_t>();
        auto size_future = size_promise.get_future();

        auto& exec = detail::event_loop::instance();
        exec.add(m_sockfd,
            detail::event_type::WRITE,
            detail::promise_completion_handler<size_t>(
                stream_write_operation<data_type>(buffer), std::move(size_promise)));

        return size_future;
    }

    template <typename data_type>
    size_t read(span<data_type> buffer) const
    {
        if (m_connection == connection_status::closed)
        {
            throw std::runtime_error{"Connection already closed."};
        }

        auto read_op = stream_read_operation<data_type>(buffer);
        return read_op(m_sockfd);
    }

    template <typename data_type>
    std::optional<size_t> read(span<data_type> buffer, const std::chrono::duration<int64_t, std::milli>& timeout) const
    {
        if (m_connection == connection_status::closed)
        {
            throw std::runtime_error{"Connection already closed."};
        }

        auto mut = std::mutex();
        auto cv = std::condition_variable();
        auto lock = std::unique_lock<std::mutex>{mut};

        auto& exec = detail::event_loop::instance();
        exec.add(
            m_sockfd, detail::event_type::READ, detail::no_return_completion_handler([&cv](int) { cv.notify_one(); }));

        // Wait for given timeout
        const auto condition_status = cv.wait_for(lock, timeout);
        if (condition_status == std::cv_status::no_timeout)
        {
            return read(buffer);
        }
        else
        {
            exec.remove(m_sockfd, detail::event_type::READ);
            return std::nullopt;
        }
    }

    template <typename data_type, typename callback_type>
    void async_read(span<data_type> buffer, callback_type&& callback) const
    {
        auto& exec = detail::event_loop::instance();
        exec.add(m_sockfd,
            detail::event_type::READ,
            detail::callback_completion_handler<size_t>(
                stream_read_operation<data_type>(buffer), std::forward<callback_type>(callback)));
    }

#if __cplusplus >= 202002L
    template <typename data_type>
    op_awaitable<size_t, stream_read_operation<data_type>> async_read(span<data_type> buffer) const
    {
        return op_awaitable<size_t, stream_read_operation<data_type>>(
            m_sockfd, stream_read_operation<data_type>(buffer), detail::event_type::READ);
    }
#endif

    template <typename data_type>
    std::future<size_t> promised_read(span<data_type> buffer) const
    {
        auto size_promise = std::promise<size_t>();
        auto size_future = size_promise.get_future();

        auto& exec = detail::event_loop::instance();
        exec.add(m_sockfd,
            detail::event_type::READ,
            detail::promise_completion_handler<size_t>(
                stream_read_operation<data_type>(buffer), std::move(size_promise)));

        return size_future;
    }
};

/// Using declarations for shorthand usage of templated tcp_connection types
using tcp_connection_v4 = tcp_connection<ip_version::v4>;
using tcp_connection_v6 = tcp_connection<ip_version::v6>;

template <ip_version ip_ver_v>
class tcp_acceptor : public detail::base_socket
{
protected:
    enum class acceptor_state : uint8_t
    {
        non_bound,
        bound
    };

    struct stream_accept_operation
    {
        tcp_connection<ip_ver_v> operator()(const int fd) const
        {
            auto client_addr = endpoint<ip_ver_v>();
            socklen_t addr_len = client_addr.addr_size;
            if (const int sock = ::accept(fd, &(client_addr.get_addr()), &addr_len);
                sock > 0 && addr_len == client_addr.addr_size)
            {
                return std::move(tcp_connection<ip_ver_v>{sock, client_addr});
            }
            else
            {
                throw std::runtime_error{"Accept operation failed."};
            }
        }
    };

    std::optional<endpoint<ip_ver_v>> m_sockaddr;

    acceptor_state m_state = acceptor_state::non_bound;

public:
    tcp_acceptor()
        : detail::base_socket{socket_type::stream, ip_ver_v}
        , m_sockaddr{std::nullopt}
        , m_state{acceptor_state::non_bound}
    {}

    tcp_acceptor(const tcp_acceptor&) = delete;
    tcp_acceptor& operator=(const tcp_acceptor&) = delete;

    tcp_acceptor(tcp_acceptor&& rhs) noexcept
        : detail::base_socket{std::move(rhs)}
        , m_state{acceptor_state::non_bound}
    {
        m_sockaddr = std::move(rhs.m_sockaddr);
    }

    tcp_acceptor& operator=(tcp_acceptor&& rhs) noexcept
    {
        // Provide a custom move assginment operator to prevent the moved object from closing the underlying file
        // descriptor
        if (this != &rhs)
        {
            detail::base_socket::operator=(std::move(rhs));

            m_sockaddr = std::move(rhs.m_sockaddr);
        }
        return *this;
    }

    tcp_acceptor(const endpoint<ip_ver_v>& bind_addr, const size_t backlog = 5)
        : detail::base_socket{socket_type::stream, ip_ver_v}
    {
        activate(bind_addr, backlog);
    }

    void activate(const endpoint<ip_ver_v>& bind_addr, const size_t backlog = 5)
    {
        if (m_state == acceptor_state::bound)
        {
            return;
        }

        m_sockaddr = bind_addr;
        if (const auto res = ::bind(m_sockfd, &(m_sockaddr->get_addr()), m_sockaddr->addr_size); res != 0)
        {
            throw std::runtime_error{"Failed to bind."};
        }

        if (const auto res = ::listen(m_sockfd, backlog); res != 0)
        {
            throw std::runtime_error{"Failed to initiate listen."};
        }

        m_state = acceptor_state::bound;
    }

    tcp_connection<ip_ver_v> accept() const
    {
        if (m_state == acceptor_state::non_bound)
        {
            throw std::runtime_error{"Socket not in listening state."};
        }

        auto accept_op = stream_accept_operation();
        return accept_op(m_sockfd);
    }

    std::optional<tcp_connection<ip_ver_v>> accept(const std::chrono::duration<int64_t, std::milli>& timeout) const
    {
        auto cv = std::condition_variable();
        auto mut = std::mutex();
        auto lock = std::unique_lock<std::mutex>{mut};

        auto& exec = detail::event_loop::instance();
        exec.add(
            m_sockfd, detail::event_type::READ, detail::no_return_completion_handler([&cv](int) { cv.notify_one(); }));

        // Wait for given timeout
        const auto condition_status = cv.wait_for(lock, timeout);
        if (condition_status == std::cv_status::no_timeout)
        {
            return std::optional<tcp_connection<ip_ver_v>>{accept()};
        }
        else
        {
            exec.remove(m_sockfd, detail::event_type::READ);
            return std::nullopt;
        }
    }

    template <typename callback_type>
    void async_accept(callback_type&& callback) const
    {
        auto& exec = detail::event_loop::instance();
        exec.add(m_sockfd,
            detail::event_type::READ,
            detail::callback_completion_handler<tcp_connection<ip_ver_v>>(
                stream_accept_operation(), std::forward<callback_type>(callback)));
    }

#if __cplusplus >= 202002L
    op_awaitable<tcp_connection<ip_ver_v>, stream_accept_operation> async_accept() const
    {
        return op_awaitable<tcp_connection<ip_ver_v>, stream_accept_operation>(
            m_sockfd, stream_accept_operation(), detail::event_type::READ);
    }
#endif

    std::future<tcp_connection<ip_ver_v>> promised_accept() const
    {
        auto acc_promise = std::promise<tcp_connection<ip_ver_v>>();
        auto acc_future = acc_promise.get_future();

        auto& exec = detail::event_loop::instance();
        exec.add(m_sockfd,
            detail::event_type::READ,
            detail::promise_completion_handler<tcp_connection<ip_ver_v>>(
                stream_accept_operation(), std::move(acc_promise)));

        return acc_future;
    }
};

/// Using declarations for shorthand usage of templated tcp_acceptor types
using tcp_acceptor_v4 = tcp_acceptor<ip_version::v4>;
using tcp_acceptor_v6 = tcp_acceptor<ip_version::v6>;

} // namespace net

#endif
