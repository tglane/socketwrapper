#ifndef SOCKETWRAPPER_NET_UDP_HPP
#define SOCKETWRAPPER_NET_UDP_HPP

#include "detail/base_socket.hpp"
#include "detail/executor.hpp"
#include "detail/utility.hpp"
#include "endpoint.hpp"
#include "span.hpp"

#include <condition_variable>
#include <future>
#include <mutex>
#include <optional>
#include <stdexcept>
#include <string_view>
#include <utility>

#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

namespace net {

template <ip_version IP_VER>
class udp_socket : public detail::base_socket
{
    enum class socket_state : uint8_t
    {
        bound,
        non_bound
    };

    template <typename T>
    struct dgram_write_operation
    {
        span<T> m_buffer_from;
        endpoint<IP_VER> m_dest;

        dgram_write_operation(span<T> buffer, endpoint<IP_VER> dest)
            : m_buffer_from(buffer)
            , m_dest(std::move(dest))
        {}

        size_t operator()(const int fd) const
        {
            size_t total = 0;
            const size_t bytes_to_send = m_buffer_from.size() * sizeof(T);
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

            return total / sizeof(T);
        }
    };

    template <typename T>
    struct dgram_read_operation
    {
        span<T> m_buffer_to;

        explicit dgram_read_operation(span<T> buffer)
            : m_buffer_to(buffer)
        {}

        std::pair<size_t, endpoint<IP_VER>> operator()(const int fd)
        {
            auto peer = endpoint<IP_VER>();
            socklen_t addr_len = peer.addr_size;
            auto* buffer_start = reinterpret_cast<char*>(m_buffer_to.get());
            if (const auto bytes =
                    ::recvfrom(fd, buffer_start, m_buffer_to.size() * sizeof(T), 0, &peer.get_addr(), &addr_len);
                bytes >= 0)
            {
                return std::make_pair(bytes / sizeof(T), std::move(peer));
            }
            else
            {
                throw std::runtime_error{"Failed to read."};
            }
        }
    };

    socket_state m_state;

    std::optional<endpoint<IP_VER>> m_sockaddr;

public:
    udp_socket(const udp_socket&) = delete;
    udp_socket& operator=(const udp_socket&) = delete;

    udp_socket()
        : detail::base_socket{socket_type::datagram, IP_VER}
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

    udp_socket(const std::string_view bind_addr_str, const uint16_t port)
        : detail::base_socket{socket_type::datagram, IP_VER}
        , m_state{socket_state::non_bound}
        , m_sockaddr{std::nullopt}
    {
        const auto bind_addr = endpoint<IP_VER>{bind_addr_str, port, socket_type::datagram};
        bind(bind_addr);
    }

    udp_socket(const endpoint<IP_VER>& bind_addr)
        : detail::base_socket{socket_type::datagram, IP_VER}
        , m_state{socket_state::non_bound}
        , m_sockaddr{std::nullopt}
    {
        bind(bind_addr);
    }

    void bind(const endpoint<IP_VER>& bind_addr)
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

    template <typename T>
    size_t send(const std::string_view addr, const uint16_t port, span<T> buffer) const
    {
        const auto addr_to = endpoint<IP_VER>{addr, port, socket_type::datagram};
        return send(addr_to, buffer);
    }

    template <typename T>
    size_t send(endpoint<IP_VER> addr, span<T> buffer) const
    {
        auto write_op = dgram_write_operation<T>(buffer, std::move(addr));
        return write_op(m_sockfd);
    }

    template <typename T>
    std::optional<std::pair<size_t, endpoint<IP_VER>>>
    send(endpoint<IP_VER> addr, span<T> buffer, const std::chrono::duration<int64_t, std::milli>& timeout) const
    {
        auto mut = std::mutex();
        auto cv = std::condition_variable();
        auto lock = std::unique_lock<std::mutex>(mut);

        auto& exec = detail::executor::instance();
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

    template <typename T, typename CALLBACK_TYPE>
    void async_send(const std::string_view addr, const uint16_t port, span<T> buffer, CALLBACK_TYPE&& callback) const
    {
        const auto addr_to = endpoint<IP_VER>{addr, port, socket_type::datagram};
        async_send(addr_to, std::move(buffer), std::forward<CALLBACK_TYPE>(callback));
    }

    template <typename T, typename CALLBACK_TYPE>
    void async_send(endpoint<IP_VER> addr, span<T> buffer, CALLBACK_TYPE&& callback) const
    {
        auto& exec = detail::executor::instance();
        exec.add(m_sockfd,
            detail::event_type::WRITE,
            detail::callback_completion_handler<size_t>(
                dgram_write_operation<T>(buffer, std::move(addr)), std::forward<CALLBACK_TYPE>(callback)));
    }

    template <typename T>
    std::future<size_t> promised_send(const std::string_view addr, const uint16_t port, span<T> buffer) const
    {
        const auto addr_to = endpoint<IP_VER>{addr, port, socket_type::datagram};
        return promised_send(std::move(addr_to), buffer);
    }

    template <typename T>
    std::future<size_t> promised_send(endpoint<IP_VER> addr, span<T> buffer) const
    {
        auto size_promise = std::promise<size_t>();
        auto size_future = size_promise.get_future();

        auto& exec = detail::executor::instance();
        exec.add(m_sockfd,
            detail::event_type::WRITE,
            detail::promise_completion_handler(
                dgram_write_operation<T>(buffer, std::move(addr)), std::move(size_promise)));

        return size_future;
    }

    template <typename T>
    std::pair<size_t, endpoint<IP_VER>> read(span<T> buffer) const
    {
        auto read_op = dgram_read_operation<T>(buffer);
        return read_op(m_sockfd);
    }

    template <typename T>
    std::optional<std::pair<size_t, endpoint<IP_VER>>> read(span<T> buffer,
        const std::chrono::duration<int64_t, std::milli>& timeout) const
    {
        auto mut = std::mutex();
        auto cv = std::condition_variable();
        auto lock = std::unique_lock<std::mutex>(mut);

        auto& exec = detail::executor::instance();
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

    template <typename T, typename CALLBACK_TYPE>
    void async_read(span<T> buffer, CALLBACK_TYPE&& callback) const
    {
        auto& exec = detail::executor::instance();
        exec.add(m_sockfd,
            detail::event_type::READ,
            detail::callback_completion_handler<std::pair<size_t, endpoint<IP_VER>>>(
                dgram_read_operation<T>(buffer), std::forward<CALLBACK_TYPE>(callback)));
    }

    template <typename T>
    std::future<std::pair<size_t, endpoint<IP_VER>>> promised_read(span<T> buffer) const
    {
        auto read_promise = std::promise<std::pair<size_t, endpoint<IP_VER>>>();
        auto read_future = read_promise.get_future();

        auto& exec = detail::executor::instance();
        exec.add(m_sockfd,
            detail::event_type::READ,
            detail::promise_completion_handler(dgram_read_operation<T>(buffer), std::move(read_promise)));

        return read_future;
    }
};

/// Using declarations for shorthand usage of templated udp_socket types
using udp_socket_v4 = udp_socket<ip_version::v4>;
using udp_socket_v6 = udp_socket<ip_version::v6>;

} // namespace net

#endif
