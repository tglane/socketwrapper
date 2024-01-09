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

    socket_state m_state;

    std::optional<endpoint<IP_VER>> m_sockaddr;

    int read_from_socket(char* const buffer, const size_t size, endpoint<IP_VER>* peer_data = nullptr) const
    {
        if(peer_data)
        {
            socklen_t addr_len = peer_data->addr_size;
            const auto bytes = ::recvfrom(this->m_sockfd, buffer, size, 0, &(peer_data->get_addr()), &addr_len);
            return bytes;
        }
        else
        {
            return ::recvfrom(this->m_sockfd, buffer, size, 0, nullptr, nullptr);
        }
    }

    int write_to_socket(const endpoint<IP_VER>& addr_to, const char* buffer, size_t length) const
    {
        return ::sendto(this->m_sockfd, buffer, length, 0, &(addr_to.get_addr()), addr_to.addr_size);
    }

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
        if(this != &rhs)
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
        if(m_state == socket_state::bound)
            return;

        m_sockaddr = bind_addr;
        if(auto res = ::bind(this->m_sockfd, &(m_sockaddr->get_addr()), m_sockaddr->addr_size); res != 0)
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
    size_t send(const endpoint<IP_VER>& addr, span<T> buffer) const
    {
        size_t total = 0;
        const size_t bytes_to_send = buffer.size() * sizeof(T);
        while(total < bytes_to_send)
        {
            if(auto bytes =
                    write_to_socket(addr, reinterpret_cast<const char*>(buffer.get()) + total, bytes_to_send - total);
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

    template <typename T, typename CALLBACK_TYPE>
    void async_send(const std::string_view addr, const uint16_t port, span<T> buffer, CALLBACK_TYPE&& callback) const
    {
        const auto addr_to = endpoint<IP_VER>{addr, port, socket_type::datagram};
        async_send(addr_to, buffer, std::forward<CALLBACK_TYPE>(callback));
    }

    template <typename T, typename CALLBACK_TYPE>
    void async_send(const endpoint<IP_VER>& addr, span<T> buffer, CALLBACK_TYPE&& callback) const
    {
        auto& exec = detail::executor::instance();
        exec.add(this->m_sockfd,
            detail::event_type::WRITE,
            detail::dgram_write_callback<IP_VER, T>{this, addr, buffer, std::forward<CALLBACK_TYPE>(callback)});
    }

    template <typename T>
    std::future<size_t> promised_send(const std::string_view addr, const uint16_t port, span<T> buffer) const
    {
        const auto addr_to = endpoint<IP_VER>{addr, port, socket_type::datagram};
        return promised_send(addr_to, buffer);
    }

    template <typename T>
    std::future<size_t> promised_send(const endpoint<IP_VER>& addr, span<T> buffer) const
    {
        auto size_promise = std::promise<size_t>();
        auto size_future = size_promise.get_future();

        auto& exec = detail::executor::instance();
        exec.add(this->m_sockfd,
            detail::event_type::WRITE,
            detail::dgram_promised_write_callback<IP_VER, T>{this, addr, buffer, std::move(size_promise)});

        return size_future;
    }

    template <typename T>
    std::pair<size_t, endpoint<IP_VER>> read(span<T> buffer) const
    {
        auto result = std::pair<size_t, endpoint<IP_VER>>{};
        auto* buffer_start = reinterpret_cast<char*>(buffer.get());
        if(const auto bytes = read_from_socket(buffer_start, buffer.size() * sizeof(T), &(result.second)); bytes >= 0)
        {
            result.first = bytes / sizeof(T);
            return result;
        }
        else
        {
            throw std::runtime_error{"Failed to read."};
        }
    }

    template <typename T>
    std::pair<size_t, std::optional<endpoint<IP_VER>>> read(span<T> buffer,
        const std::chrono::duration<int64_t, std::milli>& delay) const
    {
        // start timeout with callback as completion handler
        // inside callback have a condition variable
        // in this function use std::condition_variable::wait_for(delay)
        // when that returns no_timeout we read
        // otherwise we return
        auto mut = std::mutex();
        auto cv = std::condition_variable();
        auto lock = std::unique_lock<std::mutex>(mut);

        auto& exec = detail::executor::instance();
        exec.add(this->m_sockfd, detail::event_type::READ, detail::condition_fullfilled_callback(cv));

        // Wait for given delay or data is ready to read
        const auto condition_status = cv.wait_for(lock, delay);
        if(condition_status == std::cv_status::no_timeout)
        {
            return read(buffer);
        }
        else
        {
            return std::make_pair(0, std::nullopt);
        }
    }

    template <typename T, typename CALLBACK_TYPE>
    void async_read(span<T> buffer, CALLBACK_TYPE&& callback) const
    {
        auto& exec = detail::executor::instance();
        exec.add(this->m_sockfd,
            detail::event_type::READ,
            detail::dgram_read_callback<IP_VER, T>{this, buffer, std::forward<CALLBACK_TYPE>(callback)});
    }

    template <typename T>
    std::future<std::pair<size_t, endpoint<IP_VER>>> promised_read(span<T> buffer) const
    {
        auto read_promise = std::promise<std::pair<size_t, endpoint<IP_VER>>>();
        const auto read_future = read_promise.get_future();

        auto& exec = detail::executor::instance();
        exec.add(this->m_sockfd,
            detail::event_type::READ,
            detail::dgram_promised_read_callback<IP_VER, T>{this, buffer, std::move(read_promise)});

        return read_future;
    }
};

/// Using declarations for shorthand usage of templated udp_socket types
using udp_socket_v4 = udp_socket<ip_version::v4>;
using udp_socket_v6 = udp_socket<ip_version::v6>;

} // namespace net

#endif
