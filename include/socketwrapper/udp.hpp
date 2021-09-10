#ifndef SOCKETWRAPPER_NET_UDP_HPP
#define SOCKETWRAPPER_NET_UDP_HPP

#include "detail/async.hpp"
#include "detail/base_socket.hpp"
#include "detail/message_notifier.hpp"
#include "detail/utility.hpp"
#include "span.hpp"

#include <condition_variable>
#include <future>
#include <mutex>
#include <optional>
#include <stdexcept>
#include <string_view>
#include <utility>
#include <variant>

#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

namespace net {

template <ip_version IP_VER>
class udp_socket : public detail::base_socket
{
    using read_return_pair = std::pair<size_t, connection_info>;

    enum class socket_state : uint8_t
    {
        bound,
        non_bound
    };

public:
    udp_socket(const udp_socket&) = delete;
    udp_socket& operator=(const udp_socket&) = delete;

    udp_socket()
        : detail::base_socket {socket_type::datagram, IP_VER}
        , m_state {socket_state::non_bound}
    {}

    udp_socket(udp_socket&& rhs) noexcept
        : detail::base_socket {std::move(rhs)}
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

    udp_socket(const std::string_view bind_addr, const uint16_t port)
        : detail::base_socket {socket_type::datagram, IP_VER}
        , m_state {socket_state::non_bound}
    {
        bind(bind_addr, port);
    }

    void bind(const std::string_view bind_addr, const uint16_t port)
    {
        if(m_state == socket_state::bound)
            return;

        m_sockaddr = detail::resolve_hostname<IP_VER>(bind_addr, port, socket_type::datagram);

        if constexpr(IP_VER == ip_version::v4)
        {
            auto& sockaddr_ref = std::get<sockaddr_in>(m_sockaddr);
            if(auto res = ::bind(this->m_sockfd, reinterpret_cast<sockaddr*>(&sockaddr_ref), sizeof(sockaddr_in));
                res != 0)
                throw std::runtime_error {"Failed to bind."};
        }
        else if constexpr(IP_VER == ip_version::v6)
        {
            auto& sockaddr_ref = std::get<sockaddr_in6>(m_sockaddr);
            if(auto res = ::bind(this->m_sockfd, reinterpret_cast<sockaddr*>(&sockaddr_ref), sizeof(sockaddr_in6));
                res != 0)
                throw std::runtime_error {"Failed to bind."};
        }
        else
        {
            static_assert(IP_VER == ip_version::v4 || IP_VER == ip_version::v6);
        }

        m_state = socket_state::bound;
    }

    template <typename T>
    size_t send(const std::string_view addr, const uint16_t port, span<T>&& buffer) const
    {
        size_t total = 0;
        const size_t bytes_to_send = buffer.size() * sizeof(T);
        while(total < bytes_to_send)
        {
            if(auto bytes = write_to_socket(
                   addr, port, reinterpret_cast<const char*>(buffer.get()) + total, bytes_to_send - total);
                bytes >= 0)
                total += bytes;
            else
                throw std::runtime_error {"Failed to send."};
        }

        return total / sizeof(T);
    }

    template <typename T, typename CALLBACK_TYPE>
    void async_send(const std::string_view addr, const uint16_t port, span<T>&& buffer, CALLBACK_TYPE&& callback) const
    {
        detail::async_context::instance().add(this->m_sockfd,
            detail::async_context::WRITE,
            detail::dgram_write_callback<udp_socket<IP_VER>, T> {
                this, addr, port, std::move(buffer), std::forward<CALLBACK_TYPE>(callback)});
    }

    template <typename T>
    std::future<size_t> promised_send(const std::string_view addr, const uint16_t port, span<T>&& buffer) const
    {
        std::promise<size_t> size_promise;
        std::future<size_t> size_future = size_promise.get_future();

        detail::async_context::instance().add(this->m_sockfd,
            detail::async_context::WRITE,
            detail::dgram_promised_write_callback<udp_socket<IP_VER>, T> {
                this, addr, port, std::move(buffer), std::move(size_promise)});

        return size_future;
    }

    template <typename T>
    read_return_pair read(span<T>&& buffer) const
    {
        read_return_pair pair {};
        if(const auto bytes =
                read_from_socket(reinterpret_cast<char*>(buffer.get()), buffer.size() * sizeof(T), &(pair.second));
            bytes >= 0)
        {
            pair.first = bytes / sizeof(T);
            return pair;
        }
        else
        {
            throw std::runtime_error {"Failed to read."};
        }
    }

    template <typename T>
    std::pair<size_t, std::optional<connection_info>> read(
        span<T>&& buffer, const std::chrono::duration<int64_t, std::milli>& delay) const
    {
        auto& notifier = detail::message_notifier::instance();
        std::condition_variable cv;
        std::mutex mut;
        std::unique_lock<std::mutex> lock {mut};
        notifier.add(this->m_sockfd, &cv);

        // Wait for given delay
        const bool ready = cv.wait_for(lock, delay) == std::cv_status::no_timeout;
        notifier.remove(this->m_sockfd);

        if(ready)
            return read(span {buffer});
        else
            return {0, std::nullopt};
    }

    template <typename T, typename CALLBACK_TYPE>
    void async_read(span<T>&& buffer, CALLBACK_TYPE&& callback) const
    {
        detail::async_context::instance().add(this->m_sockfd,
            detail::async_context::READ,
            detail::dgram_read_callback<udp_socket<IP_VER>, T> {
                this, std::move(buffer), std::forward<CALLBACK_TYPE>(callback)});
    }

    template <typename T>
    std::future<read_return_pair> promised_read(span<T>&& buffer) const
    {
        std::promise<read_return_pair> read_promise;
        std::future<read_return_pair> read_future = read_promise.get_future();

        detail::async_context::instance().add(this->m_sockfd,
            detail::async_context::READ,
            detail::dgram_promised_read_callback<udp_socket<IP_VER>, T> {
                this, std::move(buffer), std::move(read_promise)});

        return read_future;
    }

private:
    int read_from_socket(char* const buffer, const size_t size, connection_info* peer_data = nullptr) const
    {
        if constexpr(IP_VER == ip_version::v4)
        {
            socklen_t flen = sizeof(sockaddr_in);
            sockaddr_in from {};
            const auto bytes = ::recvfrom(this->m_sockfd, buffer, size, 0, reinterpret_cast<sockaddr*>(&from), &flen);

            if(peer_data)
                *peer_data = detail::resolve_addrinfo<IP_VER>(reinterpret_cast<sockaddr*>(&from));

            return bytes;
        }
        else if constexpr(IP_VER == ip_version::v6)
        {
            socklen_t flen = sizeof(sockaddr_in6);
            sockaddr_in6 from {};
            const auto bytes = ::recvfrom(this->m_sockfd, buffer, size, 0, reinterpret_cast<sockaddr*>(&from), &flen);

            if(peer_data)
                *peer_data = detail::resolve_addrinfo<IP_VER>(reinterpret_cast<sockaddr*>(&from));

            return bytes;
        }
        else
        {
            static_assert(IP_VER == ip_version::v4 || IP_VER == ip_version::v6);
        }
    }

    int write_to_socket(const std::string_view addr_to, const uint16_t port, const char* buffer, size_t length) const
    {
        std::variant<sockaddr_in, sockaddr_in6> dest =
            detail::resolve_hostname<IP_VER>(addr_to, port, socket_type::datagram);

        if constexpr(IP_VER == ip_version::v4)
        {
            auto& dest_ref = std::get<sockaddr_in>(dest);
            return ::sendto(
                this->m_sockfd, buffer, length, 0, reinterpret_cast<sockaddr*>(&dest_ref), sizeof(sockaddr_in));
        }
        else if constexpr(IP_VER == ip_version::v6)
        {
            auto& dest_ref = std::get<sockaddr_in6>(dest);
            return ::sendto(
                this->m_sockfd, buffer, length, 0, reinterpret_cast<sockaddr*>(&dest_ref), sizeof(sockaddr_in6));
        }
        else
        {
            static_assert(IP_VER == ip_version::v4 || IP_VER == ip_version::v6);
        }
    }

    socket_state m_state;

    std::variant<sockaddr_in, sockaddr_in6> m_sockaddr = {};
};

/// Using declarations for shorthand usage of templated udp_socket types
using udp_socket_v4 = udp_socket<ip_version::v4>;
using udp_socket_v6 = udp_socket<ip_version::v6>;

} // namespace net

#endif
