#ifndef SOCKETWRAPPER_NET_UDP_HPP
#define SOCKETWRAPPER_NET_UDP_HPP

#include <condition_variable>
#include <future>
#include <mutex>
#include <optional>
#include <stdexcept>
#include <utility>

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
class udp_socket : public detail::base_socket
{
    enum class socket_state : uint8_t
    {
        bound,
        non_bound
    };

    template <typename data_type>
    struct dgram_write_operation
    {
        span<data_type> m_buffer_from;
        endpoint<ip_ver_v> m_dest;

        dgram_write_operation(span<data_type> buffer, endpoint<ip_ver_v> dest)
            : m_buffer_from(buffer)
            , m_dest(std::move(dest))
        {}

        size_t operator()(const int fd) const
        {
            size_t total = 0;
            const size_t bytes_to_send = m_buffer_from.size() * sizeof(data_type);
            const auto* buffer_start = reinterpret_cast<const char*>(m_buffer_from.get());
            while (total < bytes_to_send)
            {
                if (const auto bytes = ::sendto(
                        fd, buffer_start + total, bytes_to_send - total, 0, &m_dest.get_addr(), m_dest.addr_size);
                    bytes >= 0)
                {
                    total += bytes;
                }
                else
                {
                    throw std::runtime_error{"Failed to send."};
                }
            }

            return total / sizeof(data_type);
        }
    };

    template <typename data_type>
    struct dgram_read_operation
    {
        span<data_type> m_buffer_to;

        explicit dgram_read_operation(span<data_type> buffer)
            : m_buffer_to(buffer)
        {}

        std::pair<size_t, endpoint<ip_ver_v>> operator()(const int fd)
        {
            auto peer = endpoint<ip_ver_v>();
            socklen_t addr_len = peer.addr_size;
            auto* buffer_start = reinterpret_cast<char*>(m_buffer_to.get());
            if (const auto bytes = ::recvfrom(
                    fd, buffer_start, m_buffer_to.size() * sizeof(data_type), 0, &peer.get_addr(), &addr_len);
                bytes >= 0)
            {
                return std::make_pair(bytes / sizeof(data_type), std::move(peer));
            }
            else
            {
                throw std::runtime_error{"Failed to read."};
            }
        }
    };

    socket_state m_state;

    std::optional<endpoint<ip_ver_v>> m_sockaddr;

public:
    udp_socket(const udp_socket&) = delete;
    udp_socket& operator=(const udp_socket&) = delete;

    udp_socket()
        : detail::base_socket{socket_type::datagram, ip_ver_v}
        , m_state{socket_state::non_bound}
        , m_sockaddr{std::nullopt}
    {}

    udp_socket(udp_socket&& rhs) noexcept
        : detail::base_socket{std::move(rhs)}
    {
        m_state = rhs.m_state;
        m_sockaddr = std::move(rhs.m_sockaddr);

        rhs.m_sockfd = -1;
    }

    udp_socket& operator=(udp_socket&& rhs) noexcept
    {
        // Provide custom move assginment operator to prevent moved object from closing underlying file descriptor
        if (this != &rhs)
        {
            detail::base_socket::operator=(std::move(rhs));

            m_state = rhs.m_state;
            m_sockaddr = std::move(rhs.m_sockaddr);

            rhs.m_sockfd = -1;
        }
        return *this;
    }

    udp_socket(const endpoint<ip_ver_v>& bind_addr)
        : detail::base_socket{socket_type::datagram, ip_ver_v}
        , m_state{socket_state::non_bound}
        , m_sockaddr{std::nullopt}
    {
        bind(bind_addr);
    }

    void bind(const endpoint<ip_ver_v>& bind_addr)
    {
        if (m_state == socket_state::bound)
        {
            return;
        }

        m_sockaddr = bind_addr;
        if (auto res = ::bind(this->m_sockfd, &(m_sockaddr->get_addr()), m_sockaddr->addr_size); res != 0)
        {
            throw std::runtime_error{"Failed to bind."};
        }

        m_state = socket_state::bound;
    }

    template <typename data_type>
    size_t send(endpoint<ip_ver_v> addr, const span<data_type> buffer) const
    {
        auto write_op = dgram_write_operation<data_type>(buffer, std::move(addr));
        return write_op(m_sockfd);
    }

    template <typename data_type>
    std::optional<std::pair<size_t, endpoint<ip_ver_v>>> send(endpoint<ip_ver_v> addr,
        const span<data_type> buffer,
        const std::chrono::duration<int64_t, std::milli>& timeout) const
    {
        auto mut = std::mutex();
        auto cv = std::condition_variable();
        auto lock = std::unique_lock<std::mutex>(mut);

        auto& exec = detail::event_loop::instance();
        exec.add(
            m_sockfd, detail::event_type::WRITE, detail::no_return_completion_handler([&cv](int) { cv.notify_one(); }));

        // Wait for given timeout or data is ready to read
        const auto condition_status = cv.wait_for(lock, timeout);
        if (condition_status == std::cv_status::no_timeout)
        {
            return send(std::move(addr), buffer);
        }
        else
        {
            exec.remove(m_sockfd, detail::event_type::WRITE);
            return std::nullopt;
        }
    }

    template <typename data_type, typename callback_type>
    void async_send(endpoint<ip_ver_v> addr, const span<data_type> buffer, callback_type&& callback) const
    {
        auto& exec = detail::event_loop::instance();
        exec.add(m_sockfd,
            detail::event_type::WRITE,
            detail::callback_completion_handler<size_t>(
                dgram_write_operation<data_type>(buffer, std::move(addr)), std::forward<callback_type>(callback)));
    }

#if __cplusplus >= 202002L
    template <typename data_type>
    op_awaitable<size_t, dgram_write_operation<data_type>> async_send(endpoint<ip_ver_v> addr,
        const span<data_type> buffer) const
    {
        return op_awaitable<size_t, dgram_write_operation<data_type>>(
            m_sockfd, dgram_write_operation<data_type>(buffer, std::move(addr)), detail::event_type::WRITE);
    }
#endif

    template <typename data_type>
    std::future<size_t> promised_send(endpoint<ip_ver_v> addr, const span<data_type> buffer) const
    {
        auto size_promise = std::promise<size_t>();
        auto size_future = size_promise.get_future();

        auto& exec = detail::event_loop::instance();
        exec.add(m_sockfd,
            detail::event_type::WRITE,
            detail::promise_completion_handler(
                dgram_write_operation<data_type>(buffer, std::move(addr)), std::move(size_promise)));

        return size_future;
    }

    template <typename data_type>
    std::pair<size_t, endpoint<ip_ver_v>> read(span<data_type> buffer) const
    {
        auto read_op = dgram_read_operation<data_type>(buffer);
        return read_op(m_sockfd);
    }

    template <typename data_type>
    std::optional<std::pair<size_t, endpoint<ip_ver_v>>> read(span<data_type> buffer,
        const std::chrono::duration<int64_t, std::milli>& timeout) const
    {
        auto mut = std::mutex();
        auto cv = std::condition_variable();
        auto lock = std::unique_lock<std::mutex>(mut);

        auto& exec = detail::event_loop::instance();
        exec.add(
            m_sockfd, detail::event_type::READ, detail::no_return_completion_handler([&cv](int) { cv.notify_one(); }));

        // Wait for given timeout or data is ready to read
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
            detail::callback_completion_handler<std::pair<size_t, endpoint<ip_ver_v>>>(
                dgram_read_operation<data_type>(buffer), std::forward<callback_type>(callback)));
    }

#if __cplusplus >= 202002L
    template <typename data_type>
    op_awaitable<std::pair<size_t, endpoint<ip_ver_v>>, dgram_read_operation<data_type>> async_read(
        span<data_type> buffer) const
    {
        return op_awaitable<std::pair<size_t, endpoint<ip_ver_v>>, dgram_read_operation<data_type>>(
            m_sockfd, dgram_read_operation<data_type>(buffer), detail::event_type::READ);
    }
#endif

    template <typename data_type>
    std::future<std::pair<size_t, endpoint<ip_ver_v>>> promised_read(span<data_type> buffer) const
    {
        auto read_promise = std::promise<std::pair<size_t, endpoint<ip_ver_v>>>();
        auto read_future = read_promise.get_future();

        auto& exec = detail::event_loop::instance();
        exec.add(m_sockfd,
            detail::event_type::READ,
            detail::promise_completion_handler(dgram_read_operation<data_type>(buffer), std::move(read_promise)));

        return read_future;
    }
};

/// Using declarations for shorthand usage of templated udp_socket types
using udp_socket_v4 = udp_socket<ip_version::v4>;
using udp_socket_v6 = udp_socket<ip_version::v6>;

} // namespace net

#endif
