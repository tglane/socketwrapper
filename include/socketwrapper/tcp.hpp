#ifndef SOCKETWRAPPER_NET_TCP_HPP
#define SOCKETWRAPPER_NET_TCP_HPP

#include <condition_variable>
#include <functional>
#include <future>
#include <mutex>
#include <optional>
#include <stdexcept>

#include <netinet/in.h>
#include <sys/errno.h>
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
        int m_fd;

        stream_write_operation(int fd, span<data_type> buffer)
            : m_buffer_to(buffer)
            , m_fd(fd)
        {}

        size_t operator()() const
        {
            size_t total = 0;
            const size_t bytes_to_send = m_buffer_to.size() * sizeof(data_type);
            while (total < bytes_to_send)
            {
                switch (const auto bytes = ::send(m_fd,
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
        int m_fd;

        stream_read_operation(int fd, span<data_type> buffer)
            : m_buffer_from(buffer)
            , m_fd(fd)
        {}

        size_t operator()()
        {
            auto* buffer_start = reinterpret_cast<char*>(m_buffer_from.get());
            switch (const auto bytes = ::recv(m_fd, buffer_start, m_buffer_from.size() * sizeof(data_type), 0); bytes)
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

    struct no_op_operation
    {
        void operator()() const
        {}
    };

    std::optional<endpoint<ip_ver_v>> m_peer;

    mutable connection_status m_connection;

    tcp_connection(const int socket_fd, endpoint<ip_ver_v> peer_addr)
        : detail::base_socket{socket_fd, ip_ver_v}
        , m_peer{std::move(peer_addr)}
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

    tcp_connection(endpoint<ip_ver_v> conn_addr)
        : detail::base_socket{socket_type::stream, ip_ver_v}
        , m_connection{connection_status::closed}
    {
        connect(std::move(conn_addr));
    }

    virtual void connect(endpoint<ip_ver_v> conn_addr)
    {
        if (m_connection != connection_status::closed)
        {
            throw std::runtime_error("Already connected.");
        }

        if (const auto res = ::connect(m_sockfd, &(conn_addr.get_addr()), conn_addr.addr_size); res == -1)
        {
            // Check socket error to make sure that we want to wait for a connection to be established
            if (auto error = check_error(); error.has_value() && error.value() != socket_error::in_progress)
            {
                throw std::runtime_error{"Failed to complete connect."};
            }

            // IO pending so we register an event and wait
            auto mut = std::mutex();
            auto cv = std::condition_variable();
            auto lock = std::unique_lock<std::mutex>(mut);

            auto& exec = detail::event_loop::instance();
            exec.spawn(m_sockfd,
                detail::event_type::WRITE,
                detail::no_return_completion_handler([&cv]() { cv.notify_one(); }));

            // Wait for given timeout or data is ready to read
            cv.wait(lock);
        }

        // Successfully connected
        m_peer = std::move(conn_addr);
        m_connection = connection_status::connected;
    }

    template <typename callback_type>
    void async_connect(endpoint<ip_ver_v> conn_addr, callback_type&& callback)
    {
        if (m_connection != connection_status::closed)
        {
            throw std::runtime_error("Already connected.");
        }

        if (const auto res = ::connect(m_sockfd, &(conn_addr.get_addr()), conn_addr.addr_size); res == -1)
        {
            // Check socket error to make sure that we want to wait for a connection to be established
            if (auto error = check_error(); error.has_value() && error.value() != socket_error::in_progress)
            {
                throw std::runtime_error{"Failed to complete connect."};
            }

            // IO pending so we register an event and wait
            auto& exec = detail::event_loop::instance();
            exec.spawn(m_sockfd,
                detail::event_type::WRITE,
                detail::callback_completion_handler<void>(
                    [fd = m_sockfd]()
                    {
                        // Check error
                        int opt_val = 0;
                        unsigned int opt_val_len = sizeof(opt_val);
                        if (::getsockopt(fd, SOL_SOCKET, SO_ERROR, &opt_val, &opt_val_len) == -1)
                        {
                            throw std::runtime_error("Failed to read socket error.");
                        }
                    },
                    std::forward<callback_type>(callback)));
        }
        else
        {
            // TODO Enqueue the callback into the threadpool with an exception(?) set
        }

        // Successfully connected
        m_peer = std::move(conn_addr);
        m_connection = connection_status::connected;
    }

#if __cplusplus >= 202002L
    op_awaitable<void, no_op_operation> co_connect(endpoint<ip_ver_v> conn_addr)
    {
        if (m_connection != connection_status::closed)
        {
            throw std::runtime_error("Already connected.");
        }

        auto awaitable = op_awaitable<void, no_op_operation>(m_sockfd, no_op_operation(), detail::event_type::WRITE);

        if (const auto res = ::connect(m_sockfd, &(conn_addr.get_addr()), conn_addr.addr_size); res == -1)
        {
            // Check socket error to make sure that we want to wait for a connection to be established
            if (auto error = check_error(); error.has_value() && error.value() != socket_error::in_progress)
            {
                throw std::runtime_error{"Failed to complete connect."};
            }
        }
        else
        {
            // TODO: What to do here?
        }

        // Successfully connected
        m_peer = std::move(conn_addr);
        m_connection = connection_status::connected;

        return awaitable;
    }
#endif

    std::future<void> promised_connect(endpoint_v4 conn_addr)
    {
        if (m_connection != connection_status::closed)
        {
            throw std::runtime_error("Already connected.");
        }

        auto conn_promise = std::promise<void>();
        auto conn_fut = conn_promise.get_future();

        if (const auto res = ::connect(m_sockfd, &(conn_addr.get_addr()), conn_addr.addr_size); res == -1)
        {
            // Check socket error to make sure that we want to wait for a connection to be established
            if (auto error = check_error(); error.has_value() && error.value() != socket_error::in_progress)
            {
                conn_promise.set_exception(std::exception_ptr());
            }

            // IO pending so we register an event and wait
            auto& exec = detail::event_loop::instance();
            exec.spawn(m_sockfd,
                detail::event_type::WRITE,
                detail::promise_completion_handler<size_t>([]() {}, std::move(conn_promise)));
        }
        else
        {
            conn_promise.set_value();
        }

        // Successfully connected
        m_peer = std::move(conn_addr);
        m_connection = connection_status::connected;

        return conn_fut;
    }

    template <typename data_type>
    std::optional<size_t> write(span<data_type> buffer,
        const std::optional<std::reference_wrapper<const std::chrono::duration<int64_t, std::milli>>> timeout =
            std::nullopt) const
    {
        if (m_connection == connection_status::closed)
        {
            throw std::runtime_error{"Connection already closed."};
        }

        auto mut = std::mutex();
        auto cv = std::condition_variable();
        auto lock = std::unique_lock<std::mutex>{mut};

        auto& exec = detail::event_loop::instance();
        exec.spawn(
            m_sockfd, detail::event_type::WRITE, detail::no_return_completion_handler([&cv]() { cv.notify_one(); }));

        // Wait for given timeout
        auto result = std::optional<size_t>{};

        if (timeout.has_value())
        {
            const auto condition_status = cv.wait_for(lock, timeout->get());
            if (condition_status != std::cv_status::no_timeout)
            {
                exec.remove(m_sockfd, detail::event_type::WRITE);
                return result;
            }
        }
        else
        {
            cv.wait(lock);
        }

        auto write_op = stream_write_operation<data_type>(m_sockfd, buffer);
        result.emplace(write_op());
        return result;
    }

    template <typename data_type, typename callback_type>
    void async_write(span<data_type> buffer, callback_type&& callback) const
    {
        auto& exec = detail::event_loop::instance();
        exec.spawn(m_sockfd,
            detail::event_type::WRITE,
            detail::callback_completion_handler<size_t>(
                stream_write_operation<data_type>(m_sockfd, buffer), std::forward<callback_type>(callback)));
    }

#if __cplusplus >= 202002L
    template <typename data_type>
    op_awaitable<size_t, stream_write_operation<data_type>> co_write(span<data_type> buffer) const
    {
        return op_awaitable<size_t, stream_write_operation<data_type>>(
            m_sockfd, stream_write_operation<data_type>(m_sockfd, buffer), detail::event_type::WRITE);
    }
#endif

    template <typename data_type>
    std::future<size_t> promised_write(span<data_type> buffer) const
    {
        auto size_promise = std::promise<size_t>();
        auto size_future = size_promise.get_future();

        auto& exec = detail::event_loop::instance();
        exec.spawn(m_sockfd,
            detail::event_type::WRITE,
            detail::promise_completion_handler<size_t>(
                stream_write_operation<data_type>(m_sockfd, buffer), std::move(size_promise)));

        return size_future;
    }

    template <typename data_type>
    std::optional<size_t> read(span<data_type> buffer,
        const std::optional<std::reference_wrapper<const std::chrono::duration<int64_t, std::milli>>> timeout =
            std::nullopt) const
    {
        if (m_connection == connection_status::closed)
        {
            throw std::runtime_error{"Connection already closed."};
        }

        auto mut = std::mutex();
        auto cv = std::condition_variable();
        auto lock = std::unique_lock<std::mutex>{mut};

        auto& exec = detail::event_loop::instance();
        exec.spawn(
            m_sockfd, detail::event_type::READ, detail::no_return_completion_handler([&cv]() { cv.notify_one(); }));

        // Wait for given timeout
        auto result = std::optional<size_t>{};
        if (timeout.has_value())
        {
            const auto condition_status = cv.wait_for(lock, timeout->get());
            if (condition_status != std::cv_status::no_timeout)
            {
                exec.remove(m_sockfd, detail::event_type::READ);
                return result;
            }
        }
        else
        {
            cv.wait(lock);
        }

        auto read_op = stream_read_operation<data_type>(m_sockfd, buffer);
        result.emplace(read_op());
        return result;
    }

    template <typename data_type, typename callback_type>
    void async_read(span<data_type> buffer, callback_type&& callback) const
    {
        auto& exec = detail::event_loop::instance();
        exec.spawn(m_sockfd,
            detail::event_type::READ,
            detail::callback_completion_handler<size_t>(
                stream_read_operation<data_type>(m_sockfd, buffer), std::forward<callback_type>(callback)));
    }

#if __cplusplus >= 202002L
    template <typename data_type>
    op_awaitable<size_t, stream_read_operation<data_type>> co_read(span<data_type> buffer) const
    {
        return op_awaitable<size_t, stream_read_operation<data_type>>(
            m_sockfd, stream_read_operation<data_type>(m_sockfd, buffer), detail::event_type::READ);
    }
#endif

    template <typename data_type>
    std::future<size_t> promised_read(span<data_type> buffer) const
    {
        auto size_promise = std::promise<size_t>();
        auto size_future = size_promise.get_future();

        auto& exec = detail::event_loop::instance();
        exec.spawn(m_sockfd,
            detail::event_type::READ,
            detail::promise_completion_handler<size_t>(
                stream_read_operation<data_type>(m_sockfd, buffer), std::move(size_promise)));

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
        int m_fd;

        stream_accept_operation(int fd)
            : m_fd(fd)
        {}

        tcp_connection<ip_ver_v> operator()() const
        {
            auto client_addr = endpoint<ip_ver_v>();
            socklen_t addr_len = client_addr.addr_size;
            if (const int sock = ::accept(m_fd, &(client_addr.get_addr()), &addr_len);
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
        listen(bind_addr, backlog);
    }

    void listen(const endpoint<ip_ver_v>& bind_addr, const size_t backlog = 5)
    {
        if (m_state == acceptor_state::bound)
        {
            return;
        }

        if (const auto res = ::bind(m_sockfd, &(bind_addr.get_addr()), bind_addr.addr_size); res != 0)
        {
            throw std::runtime_error{"Failed to bind."};
        }

        if (const auto res = ::listen(m_sockfd, backlog); res != 0)
        {
            throw std::runtime_error{"Failed to initiate listen."};
        }

        m_sockaddr = std::move(bind_addr);
        m_state = acceptor_state::bound;
    }

    std::optional<tcp_connection<ip_ver_v>> accept(
        const std::optional<std::reference_wrapper<const std::chrono::duration<int64_t, std::milli>>> timeout =
            std::nullopt) const
    {
        auto cv = std::condition_variable();
        auto mut = std::mutex();
        auto lock = std::unique_lock<std::mutex>{mut};

        auto& exec = detail::event_loop::instance();
        exec.spawn(
            m_sockfd, detail::event_type::READ, detail::no_return_completion_handler([&cv]() { cv.notify_one(); }));

        auto result = std::optional<tcp_connection<ip_ver_v>>{};

        // Wait for given timeout
        if (timeout.has_value())
        {
            const auto condition_status = cv.wait_for(lock, timeout->get());
            if (condition_status != std::cv_status::no_timeout)
            {
                exec.remove(m_sockfd, detail::event_type::READ);
                return result;
            }
        }
        else
        {
            cv.wait(lock);
        }

        auto accept_op = stream_accept_operation(m_sockfd);
        result.emplace(accept_op());
        return result;
    }

    template <typename callback_type>
    void async_accept(callback_type&& callback) const
    {
        auto& exec = detail::event_loop::instance();
        exec.spawn(m_sockfd,
            detail::event_type::READ,
            detail::callback_completion_handler<tcp_connection<ip_ver_v>>(
                stream_accept_operation(m_sockfd), std::forward<callback_type>(callback)));
    }

#if __cplusplus >= 202002L
    op_awaitable<tcp_connection<ip_ver_v>, stream_accept_operation> co_accept() const
    {
        return op_awaitable<tcp_connection<ip_ver_v>, stream_accept_operation>(
            m_sockfd, stream_accept_operation(m_sockfd), detail::event_type::READ);
    }
#endif

    std::future<tcp_connection<ip_ver_v>> promised_accept() const
    {
        auto acc_promise = std::promise<tcp_connection<ip_ver_v>>();
        auto acc_future = acc_promise.get_future();

        auto& exec = detail::event_loop::instance();
        exec.spawn(m_sockfd,
            detail::event_type::READ,
            detail::promise_completion_handler<tcp_connection<ip_ver_v>>(
                stream_accept_operation(m_sockfd), std::move(acc_promise)));

        return acc_future;
    }
};

/// Using declarations for shorthand usage of templated tcp_acceptor types
using tcp_acceptor_v4 = tcp_acceptor<ip_version::v4>;
using tcp_acceptor_v6 = tcp_acceptor<ip_version::v6>;

} // namespace net

#endif
