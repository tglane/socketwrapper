#ifndef SOCKETWRAPPER_NET_UDP_HPP
#define SOCKETWRAPPER_NET_UDP_HPP

#include "span.hpp"
#include "detail/utility.hpp"
#include "detail/async.hpp"
#include "detail/message_notifier.hpp"

#include <string_view>
#include <utility>
#include <variant>
#include <optional>
#include <mutex>
#include <condition_variable>
#include <stdexcept>

#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>

namespace net {

template<ip_version IP_VER>
class udp_socket
{

    enum class socket_mode : uint8_t
    {
        bound,
        non_bound
    };

public:

    udp_socket(const udp_socket&) = delete;
    udp_socket& operator=(const udp_socket&) = delete;

    udp_socket()
        : m_sockfd {::socket(static_cast<uint8_t>(IP_VER), static_cast<uint8_t>(socket_type::datagram), 0)},
          m_family {IP_VER},
          m_mode {socket_mode::non_bound}
    {}

    udp_socket(udp_socket&& rhs) noexcept
    {
        *this = std::move(rhs);
    }

    udp_socket& operator=(udp_socket&& rhs) noexcept
    {
        // Provide custom move assginment operator to prevent moved object from closing underlying file descriptor
        if(this != &rhs)
        {
            m_sockfd = rhs.m_sockfd;
            m_family = rhs.m_family;
            m_mode = rhs.m_mode;
            m_sockaddr = std::move(rhs.m_sockaddr);

            rhs.m_sockfd = -1;
        }
        return *this;
    }

    udp_socket(const std::string_view bind_addr, const uint16_t port)
        : m_sockfd {::socket(static_cast<uint8_t>(IP_VER), static_cast<uint8_t>(socket_type::datagram), 0)},
          m_family {IP_VER},
          m_mode {socket_mode::bound}
    {
        if(m_sockfd == -1)
            throw std::runtime_error {"Failed to create socket."};

        const int reuse = 1;
        if(::setsockopt(m_sockfd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(int)) < 0)
            throw std::runtime_error {"Failed to set address reuseable."};

#ifdef SO_REUSEPORT
        if(::setsockopt(m_sockfd, SOL_SOCKET, SO_REUSEPORT, &reuse, sizeof(int)) < 0)
            throw std::runtime_error {"Failed to set port reuseable."};
#endif

        if(detail::resolve_hostname<IP_VER>(bind_addr, port, socket_type::datagram, m_sockaddr) != 0)
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
    }

    ~udp_socket()
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

    template<typename T>
    size_t send(const std::string_view addr, const uint16_t port, span<T>&& buffer) const
    {
        size_t total = 0;
        const size_t bytes_to_send = buffer.size() * sizeof(T);
        while(total < bytes_to_send)
        {
            if(auto bytes = write_to_socket(addr, port, reinterpret_cast<const char*>(buffer.get()) + total,
                bytes_to_send - total); bytes >= 0)
                total += bytes;
            else
                throw std::runtime_error {"Failed to send."};
        }

        return total / sizeof(T);
    }

    template<typename T, typename CALLBACK_TYPE>
    void async_send(const std::string_view addr, const uint16_t port, span<T>&& buffer, CALLBACK_TYPE&& callback) const
    {
        detail::async_context::instance().add(
            m_sockfd,
            detail::async_context::WRITE,
            [this, addr, port, buffer = std::move(buffer), func = std::forward<CALLBACK_TYPE>(callback)]()
            {
                size_t bytes_written = send(addr, port, span {buffer});
                func(bytes_written);
            }
        );
    }

    template<typename T>
    std::pair<size_t, connection_info> read(span<T>&& buffer) const
    {
        std::pair<size_t, connection_info> pair {};
        if(const auto bytes = read_from_socket(reinterpret_cast<char*>(buffer.get()), buffer.size() * sizeof(T), &(pair.second)); bytes >= 0)
        {
            pair.first = bytes / sizeof(T);
            return pair;
        }
        else
        {
            throw std::runtime_error {"Failed to read."};
        }
    }

    template<typename T>
    std::pair<size_t, std::optional<connection_info>> read(span<T>&& buffer, const std::chrono::duration<int64_t, std::milli>& delay) const
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
            return read(span {buffer});
        else
            return {0, std::nullopt};
    }

    template<typename T, typename CALLBACK_TYPE>
    void async_read(span<T>&& buffer, CALLBACK_TYPE&& callback) const
    {
        detail::async_context::instance().add(
            m_sockfd,
            detail::async_context::READ,
            [this, buffer = std::move(buffer), func = std::forward<CALLBACK_TYPE>(callback)]()
            {
                auto [bytes_read, connection] = read(span {buffer});
                func(bytes_read);
            }
        );
    }

private:

    int read_from_socket(char* const buffer, const size_t size, connection_info* peer_data = nullptr) const
    {
        if constexpr(IP_VER == ip_version::v4)
        {
            socklen_t flen = sizeof(sockaddr_in);
            sockaddr_in from {};
            const auto bytes = ::recvfrom(m_sockfd, buffer, size, 0, reinterpret_cast<sockaddr*>(&from), &flen);

            if(peer_data)
                *peer_data = detail::resolve_addrinfo<IP_VER>(reinterpret_cast<sockaddr*>(&from));

            return bytes;
        }
        else if constexpr(IP_VER == ip_version::v6)
        {
            socklen_t flen = sizeof(sockaddr_in6);
            sockaddr_in6 from {};
            const auto bytes = ::recvfrom(m_sockfd, buffer, size, 0, reinterpret_cast<sockaddr*>(&from), &flen);

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
        std::variant<sockaddr_in, sockaddr_in6> dest;
        if(detail::resolve_hostname<IP_VER>(addr_to, port, socket_type::datagram, dest) != 0)
            throw std::runtime_error {"Failed to resolve hostname."};

        if constexpr(IP_VER == ip_version::v4)
        {
            auto& dest_ref = std::get<sockaddr_in>(dest);
            return ::sendto(m_sockfd, buffer, length, 0, reinterpret_cast<sockaddr*>(&dest_ref), sizeof(sockaddr_in));
        }
        else if constexpr(IP_VER == ip_version::v6)
        {
            auto& dest_ref = std::get<sockaddr_in6>(dest);
            return ::sendto(m_sockfd, buffer, length, 0, reinterpret_cast<sockaddr*>(&dest_ref), sizeof(sockaddr_in6));
        }
        else
        {
            static_assert(IP_VER == ip_version::v4 || IP_VER == ip_version::v6);
        }
    }

    int m_sockfd;

    ip_version m_family;

    socket_mode m_mode;

    std::variant<sockaddr_in, sockaddr_in6> m_sockaddr = {};

};

/// Using declarations for shorthand usage of templated udp_socket types
using udp_socket_v4 = udp_socket<ip_version::v4>;
using udp_socket_v6 = udp_socket<ip_version::v6>;


} // namespace net

#endif
