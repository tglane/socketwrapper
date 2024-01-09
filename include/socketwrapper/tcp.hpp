#ifndef SOCKETWRAPPER_NET_TCP_HPP
#define SOCKETWRAPPER_NET_TCP_HPP

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

#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

namespace net {

template <ip_version IP_VER>
class tcp_connection : public detail::base_socket
{
protected:
    enum class connection_status : uint8_t
    {
        closed,
        connected
    };

    std::optional<endpoint<IP_VER>> m_peer;

    mutable connection_status m_connection;

    tcp_connection(const int socket_fd, const endpoint<IP_VER>& peer_addr)
        : detail::base_socket{socket_fd, IP_VER}
        , m_peer{peer_addr}
        , m_connection{connection_status::connected}
    {}

    virtual int read_from_socket(char* const buffer_to, size_t bytes_to_read) const
    {
        return ::recv(this->m_sockfd, buffer_to, bytes_to_read, 0);
    }

    virtual int write_to_socket(const char* buffer_from, size_t bytes_to_write) const
    {
        return ::send(this->m_sockfd, buffer_from, bytes_to_write, 0);
    }

    template <ip_version>
    friend class tcp_acceptor;

public:
    tcp_connection()
        : detail::base_socket{socket_type::stream, IP_VER}
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
        : detail::base_socket{socket_type::stream, IP_VER}
        , m_connection{connection_status::closed}
    {
        const auto addr = endpoint<IP_VER>{conn_addr, port_to, socket_type::stream};
        connect(addr);
    }

    tcp_connection(const endpoint<IP_VER>& conn_addr)
        : detail::base_socket{socket_type::stream, IP_VER}
        , m_connection{connection_status::closed}
    {
        connect(conn_addr);
    }

    virtual void connect(const endpoint<IP_VER>& conn_addr)
    {
        if(m_connection != connection_status::closed)
            return;

        m_peer = conn_addr;
        if(const auto res = ::connect(this->m_sockfd, &(m_peer->get_addr()), m_peer->addr_size); res != 0)
            throw std::runtime_error{"Failed to connect."};

        m_connection = connection_status::connected;
    }

    template <typename T>
    size_t send(span<T> buffer) const
    {
        if(m_connection == connection_status::closed)
            throw std::runtime_error{"Connection already closed."};

        size_t total = 0;
        const size_t bytes_to_send = buffer.size() * sizeof(T);
        while(total < bytes_to_send)
        {
            switch(const auto bytes =
                       write_to_socket(reinterpret_cast<const char*>(buffer.get()) + total, bytes_to_send - total);
                   bytes)
            {
                case -1:
                    // TODO Check for errors that must be handled
                    throw std::runtime_error{"Failed to read."};
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

    template <typename T, typename CALLBACK_TYPE>
    void async_send(span<T> buffer, CALLBACK_TYPE&& callback) const
    {
        auto& exec = detail::executor::instance();
        exec.add(this->m_sockfd,
            detail::event_type::WRITE,
            detail::stream_write_callback<tcp_connection<IP_VER>, T>{
                this, buffer, std::forward<CALLBACK_TYPE>(callback)});
    }

    template <typename T>
    std::future<size_t> promised_send(span<T> buffer) const
    {
        auto size_promise = std::promise<size_t>();
        auto size_future = size_promise.get_future();

        auto& exec = detail::executor::instance();
        exec.add(this->m_sockfd,
            detail::event_type::WRITE,
            detail::stream_promised_write_callback<tcp_connection<IP_VER>, T>{this, buffer, std::move(size_promise)});

        return size_future;
    }

    template <typename T>
    size_t read(span<T> buffer) const
    {
        if(m_connection == connection_status::closed)
            throw std::runtime_error{"Connection already closed."};

        switch(const auto bytes = read_from_socket(reinterpret_cast<char*>(buffer.get()), buffer.size() * sizeof(T));
               bytes)
        {
            case -1:
                // TODO Maybe handle errno to get some error code?
                throw std::runtime_error{"Failed to read."};
            case 0:
                m_connection = connection_status::closed;
                // fall through
            default:
                return bytes / sizeof(T);
        }
    }

    template <typename T>
    size_t read(span<T> buffer, const std::chrono::duration<int64_t, std::milli>& delay) const
    {
        if(m_connection == connection_status::closed)
        {
            throw std::runtime_error{"Connection already closed."};
        }

        auto mut = std::mutex();
        auto cv = std::condition_variable();
        auto lock = std::unique_lock<std::mutex>{mut};

        auto& exec = detail::executor::instance();
        exec.add(this->m_sockfd, detail::event_type::READ, detail::condition_fullfilled_callback(cv));

        // Wait for given delay
        const auto condition_status = cv.wait_for(lock, delay);
        if(condition_status == std::cv_status::no_timeout)
        {
            return read(buffer);
        }
        else
        {
            return 0;
        }
    }

    template <typename T, typename CALLBACK_TYPE>
    void async_read(span<T> buffer, CALLBACK_TYPE&& callback) const
    {
        auto& exec = detail::executor::instance();
        exec.add(this->m_sockfd,
            detail::event_type::READ,
            detail::stream_read_callback<tcp_connection<IP_VER>, T>{
                this, buffer, std::forward<CALLBACK_TYPE>(callback)});
    }

    template <typename T>
    std::future<size_t> promised_read(span<T> buffer) const
    {
        auto size_promise = std::promise<size_t>();
        auto size_future = size_promise.get_future();

        auto& exec = detail::executor::instance();
        exec.add(this->m_sockfd,
            detail::event_type::READ,
            detail::stream_promised_read_callback<tcp_connection<IP_VER>, T>{this, buffer, std::move(size_promise)});

        return size_future;
    }
};

/// Using declarations for shorthand usage of templated tcp_connection types
using tcp_connection_v4 = tcp_connection<ip_version::v4>;
using tcp_connection_v6 = tcp_connection<ip_version::v6>;

template <ip_version IP_VER>
class tcp_acceptor : public detail::base_socket
{
protected:
    enum class acceptor_state : uint8_t
    {
        non_bound,
        bound
    };

    std::optional<endpoint<IP_VER>> m_sockaddr;

    acceptor_state m_state = acceptor_state::non_bound;

public:
    tcp_acceptor()
        : detail::base_socket{socket_type::stream, IP_VER}
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
        if(this != &rhs)
        {
            detail::base_socket::operator=(std::move(rhs));

            m_sockaddr = std::move(rhs.m_sockaddr);
        }
        return *this;
    }

    tcp_acceptor(const std::string_view bind_addr, const uint16_t port, const size_t backlog = 5)
        : detail::base_socket{socket_type::stream, IP_VER}
        , m_state{acceptor_state::non_bound}
    {
        const auto addr = endpoint<IP_VER>{bind_addr, port, socket_type::stream};
        activate(addr, backlog);
    }

    tcp_acceptor(const endpoint<IP_VER>& bind_addr, const size_t backlog = 5)
        : detail::base_socket{socket_type::stream, IP_VER}
    {
        activate(bind_addr, backlog);
    }

    void activate(const endpoint<IP_VER>& bind_addr, const size_t backlog = 5)
    {
        if(m_state == acceptor_state::bound)
            return;

        m_sockaddr = bind_addr;
        if(const auto res = ::bind(this->m_sockfd, &(m_sockaddr->get_addr()), m_sockaddr->addr_size); res != 0)
            throw std::runtime_error{"Failed to bind."};

        if(const auto res = ::listen(this->m_sockfd, backlog); res != 0)
            throw std::runtime_error{"Failed to initiate listen."};

        m_state = acceptor_state::bound;
    }

    tcp_connection<IP_VER> accept() const
    {
        if(m_state == acceptor_state::non_bound)
            throw std::runtime_error{"Socket not in listening state."};

        auto client_addr = endpoint<IP_VER>();
        socklen_t addr_len = client_addr.addr_size;
        if(const int sock = ::accept(this->m_sockfd, &(client_addr.get_addr()), &addr_len);
            sock > 0 && addr_len == client_addr.addr_size)
        {
            return tcp_connection<IP_VER>{sock, client_addr};
        }
        else
        {
            throw std::runtime_error{"Accept operation failed."};
        }
    }

    std::optional<tcp_connection<IP_VER>> accept(const std::chrono::duration<int64_t, std::milli>& delay) const
    {
        auto cv = std::condition_variable();
        auto mut = std::mutex();
        auto lock = std::unique_lock<std::mutex>{mut};

        auto& exec = detail::executor::instance();
        exec.add(this->m_sockfd, detail::event_type::READ, detail::condition_fullfilled_callback(cv));

        // Wait for given delay
        const auto condition_status = cv.wait_for(lock, delay);
        if(condition_status == std::cv_status::no_timeout)
        {
            return std::optional<tcp_connection<IP_VER>>{accept()};
        }
        else
        {
            return std::nullopt;
        }
    }

    template <typename CALLBACK_TYPE>
    void async_accept(CALLBACK_TYPE&& callback) const
    {
        auto& exec = detail::executor::instance();
        exec.add(this->m_sockfd,
            detail::event_type::READ,
            detail::stream_accept_callback<tcp_acceptor<IP_VER>>{this, std::forward<CALLBACK_TYPE>(callback)});
    }

    std::future<tcp_connection<IP_VER>> promised_accept() const
    {
        auto acc_promise = std::promise<tcp_connection<IP_VER>>();
        auto acc_future = acc_promise.get_future();

        auto& exec = detail::executor::instance();
        exec.add(this->m_sockfd,
            detail::event_type::READ,
            detail::stream_promised_accept_callback<tcp_acceptor<IP_VER>>{this, std::move(acc_promise)});

        return acc_future;
    }
};

/// Using declarations for shorthand usage of templated tcp_acceptor types
using tcp_acceptor_v4 = tcp_acceptor<ip_version::v4>;
using tcp_acceptor_v6 = tcp_acceptor<ip_version::v6>;

} // namespace net

#endif
