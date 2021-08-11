#ifndef SOCKETWRAPPER_NET_UDP_HPP
#define SOCKETWRAPPER_NET_UDP_HPP

#include "span.hpp"
#include "detail/base_socket.hpp"
#include "detail/utility.hpp"
#include "detail/async.hpp"
#include "detail/message_notifier.hpp"

#include <string_view>
#include <utility>
#include <variant>
#include <future>
#include <optional>
#include <mutex>
#include <condition_variable>
#include <stdexcept>

#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>

namespace net {

template<ip_version IP_VER>
class udp_socket : public detail::base_socket
{
    using read_return_pair = std::pair<size_t, connection_info>;

    enum class socket_mode : uint8_t
    {
        bound,
        non_bound
    };

    template<typename T>
    class read_callback : public detail::abstract_socket_callback
    {
    public:

        template<typename USER_CALLBACK>
        read_callback(const udp_socket<IP_VER>* sock_ptr, span<T> view, USER_CALLBACK&& cb)
            : detail::abstract_socket_callback {sock_ptr},
              m_buffer {std::move(view)},
              m_func {std::forward<USER_CALLBACK>(cb)}
        {}

        void operator()() const override
        {
            const udp_socket<IP_VER>* ptr = static_cast<const udp_socket<IP_VER>*>(this->socket_ptr);
            auto [bytes_read, connection] = ptr->read(span {m_buffer.get(), m_buffer.size()});
            m_func(bytes_read);
        }

    private:
        span<T> m_buffer;
        std::function<void(size_t)> m_func;
    };

    template<typename T>
    class promised_read_callback : public detail::abstract_socket_callback
    {
    public:

        promised_read_callback(const udp_socket<IP_VER>* sock_ptr, span<T> view, std::promise<read_return_pair> promise)
            : detail::abstract_socket_callback {static_cast<const detail::base_socket*>(sock_ptr)},
              m_buffer {std::move(view)},
              m_promise {std::move(promise)}
        {}

        void operator()() const override
        {
            const udp_socket<IP_VER>* ptr = static_cast<const udp_socket<IP_VER>*>(this->socket_ptr);
            read_return_pair ret = ptr->read(span {m_buffer.get(), m_buffer.size()});

            m_promise.set_value(std::move(ret));
        }

    private:
        span<T> m_buffer;
        mutable std::promise<read_return_pair> m_promise;
    };

    template<typename T>
    class write_callback : public detail::abstract_socket_callback
    {
    public:

        template<typename USER_CALLBACK>
        write_callback(const udp_socket<IP_VER>* sock_ptr, std::string_view addr, uint16_t port, span<T> view, USER_CALLBACK&& cb)
            : detail::abstract_socket_callback {sock_ptr},
              m_addr {std::move(addr)},
              m_port {port},
              m_buffer {std::move(view)},
              m_func {std::forward<USER_CALLBACK>(cb)}
        {}

        void operator()() const override
        {
            const udp_socket<IP_VER>* ptr = static_cast<const udp_socket<IP_VER>*>(this->socket_ptr);
            size_t bytes_written = ptr->send(m_addr, m_port, span {m_buffer.get(), m_buffer.size()});
            m_func(bytes_written);
        }

    private:
        std::string_view m_addr;
        uint16_t m_port;
        span<T> m_buffer;
        std::function<void(size_t)> m_func;
    };

    template<typename T>
    class promised_write_callback : public detail::abstract_socket_callback
    {
    public:
        promised_write_callback(const udp_socket<IP_VER>* sock_ptr, std::string_view addr, uint16_t port, span<T> view, std::promise<size_t> promise)
            : detail::abstract_socket_callback {sock_ptr},
              m_addr {addr},
              m_port {port},
              m_buffer {std::move(view)},
              m_promise {std::move(promise)}
        {}

        void operator()() const override
        {
            const udp_socket<IP_VER>* ptr = static_cast<const udp_socket<IP_VER>*>(this->socket_ptr);
            size_t bytes_written = ptr->send(m_addr, m_port, span {m_buffer.get(), m_buffer.size()});

            m_promise.set_value(bytes_written);
        }

    private:
        std::string_view m_addr;
        uint16_t m_port;
        span<T> m_buffer;
        mutable std::promise<size_t> m_promise;
    };

public:

    udp_socket(const udp_socket&) = delete;
    udp_socket& operator=(const udp_socket&) = delete;

    udp_socket()
        : detail::base_socket {socket_type::datagram, IP_VER},
          m_mode {socket_mode::non_bound}
    {}

    udp_socket(udp_socket&& rhs) noexcept
        : detail::base_socket {std::move(rhs)}
    {
        m_mode = rhs.m_mode;
        m_sockaddr = std::move(rhs.m_sockaddr);

        rhs.m_sockfd = -1;
    }

    udp_socket& operator=(udp_socket&& rhs) noexcept
    {
        // Provide custom move assginment operator to prevent moved object from closing underlying file descriptor
        if(this != &rhs)
        {
            detail::base_socket::operator=(std::move(rhs));

            m_mode = rhs.m_mode;
            m_sockaddr = std::move(rhs.m_sockaddr);

            rhs.m_sockfd = -1;
        }
        return *this;
    }

    udp_socket(const std::string_view bind_addr, const uint16_t port)
        : detail::base_socket {socket_type::datagram, IP_VER},
          m_mode {socket_mode::bound}
    {
        if(detail::resolve_hostname<IP_VER>(bind_addr, port, socket_type::datagram, m_sockaddr) != 0)
            throw std::runtime_error {"Failed to resolve hostname."};

        if constexpr(IP_VER == ip_version::v4)
        {
            auto& sockaddr_ref = std::get<sockaddr_in>(m_sockaddr);
            if(auto res = ::bind(this->m_sockfd, reinterpret_cast<sockaddr*>(&sockaddr_ref), sizeof(sockaddr_in)); res != 0)
                throw std::runtime_error {"Failed to bind."};
        }
        else if constexpr(IP_VER == ip_version::v6)
        {
            auto& sockaddr_ref = std::get<sockaddr_in6>(m_sockaddr);
            if(auto res = ::bind(this->m_sockfd, reinterpret_cast<sockaddr*>(&sockaddr_ref), sizeof(sockaddr_in6)); res != 0)
                throw std::runtime_error {"Failed to bind."};
        }
        else
        {
            static_assert(IP_VER == ip_version::v4 || IP_VER == ip_version::v6);
        }
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
            this->m_sockfd,
            detail::async_context::WRITE,
            write_callback {this, addr, port, std::move(buffer), std::forward<CALLBACK_TYPE>(callback)}
        );
    }

    template<typename T>
    std::future<size_t> promised_send(const std::string_view addr, const uint16_t port, span<T>&& buffer) const
    {
        std::promise<size_t> size_promise;
        std::future<size_t> size_future = size_promise.get_future();

        detail::async_context::instance().add(
            this->m_sockfd,
            detail::async_context::WRITE,
            promised_write_callback<T> {this, addr, port, std::move(buffer), std::move(size_promise)}
        );

        return size_future;
    }

    template<typename T>
    read_return_pair read(span<T>&& buffer) const
    {
        read_return_pair pair {};
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
        notifier.add(this->m_sockfd, &cv);

        // Wait for given delay
        const bool ready = cv.wait_for(lock, delay) == std::cv_status::no_timeout;
        notifier.remove(this->m_sockfd);

        if(ready)
            return read(span {buffer});
        else
            return {0, std::nullopt};
    }

    template<typename T, typename CALLBACK_TYPE>
    void async_read(span<T>&& buffer, CALLBACK_TYPE&& callback) const
    {
        detail::async_context::instance().add(
            this->m_sockfd,
            detail::async_context::READ,
            read_callback {this, std::move(buffer), std::forward<CALLBACK_TYPE>(callback)}
        );
    }

    template<typename T>
    std::future<read_return_pair> promised_read(span<T>&& buffer) const
    {
        std::promise<read_return_pair> read_promise;
        std::future<read_return_pair> read_future = read_promise.get_future();

        detail::async_context::instance().add(
            this->m_sockfd,
            detail::async_context::READ,
            promised_read_callback {this, std::move(buffer), std::move(read_promise)}
        );

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
        std::variant<sockaddr_in, sockaddr_in6> dest;
        if(detail::resolve_hostname<IP_VER>(addr_to, port, socket_type::datagram, dest) != 0)
            throw std::runtime_error {"Failed to resolve hostname."};

        if constexpr(IP_VER == ip_version::v4)
        {
            auto& dest_ref = std::get<sockaddr_in>(dest);
            return ::sendto(this->m_sockfd, buffer, length, 0, reinterpret_cast<sockaddr*>(&dest_ref), sizeof(sockaddr_in));
        }
        else if constexpr(IP_VER == ip_version::v6)
        {
            auto& dest_ref = std::get<sockaddr_in6>(dest);
            return ::sendto(this->m_sockfd, buffer, length, 0, reinterpret_cast<sockaddr*>(&dest_ref), sizeof(sockaddr_in6));
        }
        else
        {
            static_assert(IP_VER == ip_version::v4 || IP_VER == ip_version::v6);
        }
    }

    socket_mode m_mode;

    std::variant<sockaddr_in, sockaddr_in6> m_sockaddr = {};

};

/// Using declarations for shorthand usage of templated udp_socket types
using udp_socket_v4 = udp_socket<ip_version::v4>;
using udp_socket_v6 = udp_socket<ip_version::v6>;


} // namespace net

#endif
