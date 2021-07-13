#ifndef SOCKETWRAPPER_NET_TCP_HPP
#define SOCKETWRAPPER_NET_TCP_HPP

#include "span.hpp"
#include "detail/base_socket.hpp"
#include "detail/utility.hpp"
#include "detail/async.hpp"
#include "detail/message_notifier.hpp"

#include <string_view>
#include <variant>
#include <optional>
#include <future>
#include <mutex>
#include <condition_variable>
#include <stdexcept>

#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>

namespace net {

template<ip_version IP_VER>
class tcp_connection : public detail::base_socket
{
protected:

    enum class connection_status : uint8_t
    {
        closed,
        connected
    };

    template<typename T>
    class read_callback : public detail::abstract_socket_callback
    {
    public:

        template<typename USER_CALLBACK>
        read_callback(const tcp_connection<IP_VER>* sock_ptr, span<T> view, USER_CALLBACK&& cb)
            : detail::abstract_socket_callback {static_cast<const detail::base_socket*>(sock_ptr)},
              m_buffer {std::move(view)},
              m_func {std::forward<USER_CALLBACK>(cb)}
        {}

        void operator()() const override
        {
            const tcp_connection<IP_VER>* ptr = static_cast<const tcp_connection<IP_VER>*>(this->socket_ptr);
            size_t bytes_read = ptr->read(span<T> {m_buffer.get(), m_buffer.size()});
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
        promised_read_callback(const tcp_connection<IP_VER>* sock_ptr, span<T> view, std::promise<size_t> promise)
            : detail::abstract_socket_callback {static_cast<const detail::base_socket*>(sock_ptr)},
              m_buffer {std::move(view)},
              m_promise {std::move(promise)}
        {}

        void operator()() const override
        {
            const tcp_connection<IP_VER>* ptr = static_cast<const tcp_connection<IP_VER>*>(this->socket_ptr);
            size_t bytes_read = ptr->read(span<T> {m_buffer.get(), m_buffer.size()});

            m_promise.set_value(bytes_read);
        }

    private:
        span<T> m_buffer;
        mutable std::promise<size_t> m_promise;
    };

    template<typename T>
    class write_callback : public detail::abstract_socket_callback
    {
    public:
        template<typename USER_CALLBACK>
        write_callback(const tcp_connection<IP_VER>* sock_ptr, span<T> view, USER_CALLBACK&& cb)
            : detail::abstract_socket_callback {static_cast<const detail::base_socket*>(sock_ptr)},
              m_buffer {std::move(view)},
              m_func {std::forward<USER_CALLBACK>(cb)}
        {}

        void operator()() const override
        {
            const tcp_connection<IP_VER>* ptr = static_cast<const tcp_connection<IP_VER>*>(this->socket_ptr);
            size_t bytes_written = ptr->send(span<T> {m_buffer.get(), m_buffer.size()});
            m_func(bytes_written);
        }

    private:
        span<T> m_buffer;
        std::function<void(size_t)> m_func;
    };

public:

    tcp_connection(const tcp_connection&) = delete;
    tcp_connection& operator=(const tcp_connection&) = delete;

    tcp_connection(tcp_connection&& rhs) noexcept
        : detail::base_socket {std::move(rhs)}
    {
        m_peer = std::move(rhs.m_peer);
        m_connection = rhs.m_connection;

        rhs.m_connection = connection_status::closed;
    }

    tcp_connection& operator=(tcp_connection&& rhs) noexcept
    {
        // Provide custom move assginment operator to prevent the moved socket from closing the underlying file descriptor
        if(this != &rhs)
        {
            detail::base_socket::operator=(std::move(rhs));

            m_peer = std::move(rhs.m_peer);
            m_connection = rhs.m_connection;

            rhs.m_connection = connection_status::closed;
        }
        return *this;
    }

    tcp_connection(const std::string_view conn_addr, const uint16_t port_to)
        : detail::base_socket {socket_type::stream, IP_VER},
          m_connection {connection_status::closed}
    {
        if(detail::resolve_hostname<IP_VER>(conn_addr, port_to, socket_type::stream, m_peer) != 0)
            throw std::runtime_error {"Failed to resolve hostname."};

        if constexpr(IP_VER == ip_version::v4)
        {
            auto& ref = std::get<sockaddr_in>(m_peer);
            if(auto res = ::connect(this->m_sockfd, reinterpret_cast<sockaddr*>(&ref), sizeof(sockaddr_in)); res != 0)
                throw std::runtime_error {"Failed to connect."};
            m_connection = connection_status::connected;
        }
        else if constexpr(IP_VER == ip_version::v6)
        {
            auto& ref = std::get<sockaddr_in6>(m_peer);
            if(auto res = ::connect(this->m_sockfd, reinterpret_cast<sockaddr*>(&ref), sizeof(sockaddr_in)); res != 0)
                throw std::runtime_error {"Failed to connect."};
            m_connection = connection_status::connected;
        }
        else
        {
            static_assert(IP_VER == ip_version::v4 || IP_VER == ip_version::v6);
        }
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
            this->m_sockfd,
            detail::async_context::WRITE,
            write_callback<T> {this, std::move(buffer), std::forward<CALLBACK_TYPE>(callback)}
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
        notifier.add(this->m_sockfd, &cv);

        // Wait for given delay
        const bool ready = cv.wait_for(lock, delay) == std::cv_status::no_timeout;
        notifier.remove(this->m_sockfd);

        if(ready)
            return read(span {buffer});
        else
            return 0;
    }

    template<typename T, typename CALLBACK_TYPE>
    void async_read(span<T>&& buffer, CALLBACK_TYPE&& callback) const
    {
        detail::async_context::instance().add(
            this->m_sockfd,
            detail::async_context::READ,
            read_callback<T> {this, std::move(buffer), std::forward<CALLBACK_TYPE>(callback)}
        );
    }

    template<typename T>
    std::future<size_t> promised_read(span<T>&& buffer) const
    {
        std::promise<size_t> size_promise;
        std::future<size_t> size_future = size_promise.get_future();

        detail::async_context::instance().add(
            this->m_sockfd,
            detail::async_context::READ,
            promised_read_callback<T> {this, std::move(buffer), std::move(size_promise)}
        );

        return size_future;
    }

protected:

    tcp_connection() = default;

    tcp_connection(const int socket_fd, const sockaddr_in& peer_addr)
        : detail::base_socket {socket_fd, ip_version::v4},
          m_peer {peer_addr},
          m_connection {connection_status::connected}
    {
        static_assert(IP_VER == ip_version::v4);
    }

    tcp_connection(const int socket_fd, const sockaddr_in6& peer_addr)
        : detail::base_socket {socket_fd, ip_version::v6},
          m_peer {peer_addr},
          m_connection {connection_status::connected}
    {
        static_assert(IP_VER == ip_version::v6);
    }

    virtual int read_from_socket(char* const buffer_to, size_t bytes_to_read) const
    {
        return ::recv(this->m_sockfd, buffer_to, bytes_to_read, 0);
    }

    virtual int write_to_socket(const char* buffer_from, size_t bytes_to_write) const
    {
        return ::send(this->m_sockfd, buffer_from, bytes_to_write, 0);
    }

    std::variant<sockaddr_in, sockaddr_in6> m_peer = {};

    mutable connection_status m_connection;

    template<ip_version>
    friend class tcp_acceptor;

};

/// Using declarations for shorthand usage of templated tcp_connection types
using tcp_connection_v4 = tcp_connection<ip_version::v4>;
using tcp_connection_v6 = tcp_connection<ip_version::v6>;


template<ip_version IP_VER>
class tcp_acceptor : public detail::base_socket
{

    class accept_callback : public detail::abstract_socket_callback
    {
    public:

        template<typename USER_CALLBACK>
        accept_callback(const tcp_acceptor<IP_VER>* sock_ptr, USER_CALLBACK&& cb)
            : detail::abstract_socket_callback {sock_ptr},
              m_func {std::forward<USER_CALLBACK>(cb)}
        {}

        void operator()() const override
        {
            const tcp_acceptor<IP_VER>* ptr = static_cast<const tcp_acceptor<IP_VER>*>(this->socket_ptr);
            m_func(ptr->accept());
        }

    private:
        std::function<void(tcp_connection<IP_VER>&&)> m_func;
    };

    class promised_accept_callback : public detail::abstract_socket_callback
    {
    public:

        promised_accept_callback(const tcp_acceptor<IP_VER>* sock_ptr, std::promise<tcp_connection<IP_VER>> promise)
            : detail::abstract_socket_callback {sock_ptr},
              m_promise {std::move(promise)}
        {}

        void operator()() const override
        {
            const tcp_acceptor<IP_VER>* ptr = static_cast<const tcp_acceptor<IP_VER>*>(this->socket_ptr);
            m_promise.set_value(ptr->accept());
        }

    private:
        mutable std::promise<tcp_connection<IP_VER>> m_promise;
    }

public:

    tcp_acceptor() = delete;
    tcp_acceptor(const tcp_acceptor&) = delete;
    tcp_acceptor& operator=(const tcp_acceptor&) = delete;

    tcp_acceptor(tcp_acceptor&& rhs) noexcept
        : detail::base_socket {std::move(rhs)}
    {
        m_sockaddr = std::move(rhs.m_sockaddr);
    }

    tcp_acceptor& operator=(tcp_acceptor&& rhs) noexcept
    {
        // Provide a custom move assginment operator to prevent the moved object from closing the underlying file descriptor
        if(this != &rhs)
        {
            detail::base_socket::operator=(std::move(rhs));

            m_sockaddr = std::move(rhs.m_sockaddr);
        }
        return *this;
    }

    tcp_acceptor(const std::string_view bind_addr, const uint16_t port, const size_t backlog = 5)
        : detail::base_socket {socket_type::stream, IP_VER}
    {
        if(detail::resolve_hostname<IP_VER>(bind_addr, port, socket_type::stream, m_sockaddr) != 0)
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

        if(const auto res = ::listen(this->m_sockfd, backlog); res != 0)
            throw std::runtime_error {"Failed to initiate listen."};
    }

    tcp_connection<IP_VER> accept() const
    {
        if constexpr(IP_VER == ip_version::v4)
        {
            sockaddr_in client {};
            socklen_t len = sizeof(sockaddr_in);
            if(const int sock = ::accept(this->m_sockfd, reinterpret_cast<sockaddr*>(&client), &len); sock > 0)
                return tcp_connection<IP_VER> {sock, client};
            else
                throw std::runtime_error {"Failed to accept."};
        }
        else if constexpr(IP_VER == ip_version::v6)
        {
            sockaddr_in6 client {};
            socklen_t len = sizeof(sockaddr_in6);
            if(const int sock = ::accept(this->m_sockfd, reinterpret_cast<sockaddr*>(&client), &len); sock > 0)
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
        notifier.add(this->m_sockfd, &cv);

        // Wait for given delay
        const bool ready = cv.wait_for(lock, delay) == std::cv_status::no_timeout;
        notifier.remove(this->m_sockfd);

        if(ready)
            return std::optional<tcp_connection<IP_VER>> {accept()};
        else
            return std::nullopt;
    }

    template<typename CALLBACK_TYPE>
    void async_accept(CALLBACK_TYPE&& callback) const
    {
        detail::async_context::instance().add(
            this->m_sockfd,
            detail::async_context::READ,
            accept_callback {this, std::forward<CALLBACK_TYPE>(callback)}
        );
    }

    std::future<tcp_connection<IP_VER>> promised_accept() const
    {
        std::promise<tcp_connection<IP_VER>> acc_promise;
        std::future<tcp_connection<IP_VER>> acc_future = acc_promise.get_future();

        detail::async_context::instance().add(
            this->m_sockfd,
            detail::async_context::READ,
            promised_accept_callback {this, std::move(acc_promise)}
        );

        return acc_future;
    }

protected:

    std::variant<sockaddr_in, sockaddr_in6> m_sockaddr {};

};

/// Using declarations for shorthand usage of templated tcp_acceptor types
using tcp_acceptor_v4 = tcp_acceptor<ip_version::v4>;
using tcp_acceptor_v6 = tcp_acceptor<ip_version::v6>;


} // namespace net

#endif
