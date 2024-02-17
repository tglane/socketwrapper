#ifndef SOCKETWRAPPER_NET_TLS_HPP
#define SOCKETWRAPPER_NET_TLS_HPP

#include "tcp.hpp"

#include <condition_variable>
#include <memory>
#include <mutex>
#include <stdexcept>
#include <string>
#include <string_view>

#include <netinet/in.h>
#include <openssl/err.h>
#include <openssl/ssl.h>

namespace net {

namespace detail {

inline void init_ssl_system()
{
    static bool initialized = false;
    if (!initialized)
    {
        SSL_library_init();
        SSL_load_error_strings();
        OpenSSL_add_ssl_algorithms();

        initialized = true;
    }
}

inline void configure_ssl_ctx(std::shared_ptr<SSL_CTX>& ctx, std::string_view cert, std::string_view key, bool server)
{
    ctx.reset(::SSL_CTX_new((server) ? TLS_server_method() : TLS_client_method()),
        [](SSL_CTX* ctx_raw)
        {
            if (ctx_raw != nullptr)
            {
                SSL_CTX_free(ctx_raw);
            }
        });
    if (ctx == nullptr)
    {
        throw std::runtime_error{"Failed to create TLS context."};
    }

    SSL_CTX_set_mode(ctx.get(), SSL_MODE_AUTO_RETRY);
    SSL_CTX_set_ecdh_auto(ctx.get(), 1);

    if (::SSL_CTX_use_certificate_file(ctx.get(), cert.data(), SSL_FILETYPE_PEM) <= 0)
    {
        throw std::runtime_error{"Failed to configure certificate from PEM file."};
    }
    if (::SSL_CTX_use_PrivateKey_file(ctx.get(), key.data(), SSL_FILETYPE_PEM) <= 0)
    {
        throw std::runtime_error{"Failed to configure private key from PEM file."};
    }
}

struct ssl_raw_deleter
{
    void operator()(SSL* ssl_raw)
    {
        if (ssl_raw != nullptr)
        {
            ::SSL_shutdown(ssl_raw);
            ::SSL_free(ssl_raw);
        }
    }
};

} // namespace detail

template <ip_version IP_VER>
class tls_connection : public tcp_connection<IP_VER>
{
    tls_connection(int socketfd, const endpoint<IP_VER>& peer_addr, std::shared_ptr<SSL_CTX> context)
        : tcp_connection<IP_VER>{socketfd, peer_addr}
        , m_context{std::move(context)}
    {
        SSL* ssl_raw = SSL_new(m_context.get());
        if (ssl_raw == nullptr)
        {
            throw std::runtime_error{"Failed to instatiate SSL structure."};
        }
        m_ssl.reset(ssl_raw);
        ::SSL_set_fd(m_ssl.get(), this->m_sockfd);

        if (const auto ret = SSL_accept(m_ssl.get()); ret != 1)
        {
            ::SSL_get_error(m_ssl.get(), ret);
            ::ERR_print_errors_fp(stderr);
            throw std::runtime_error{"Failed to accept TLS connection."};
        }
    }

    template <typename T>
    struct stream_write_operation
    {
        SSL& m_ssl;
        span<T> m_buffer_to;

        stream_write_operation(SSL& ssl, span<T> buffer)
            : m_ssl(ssl)
            , m_buffer_to(buffer)
        {}

        size_t operator()(const int) const
        {
            size_t total = 0;
            const size_t bytes_to_send = m_buffer_to.size() * sizeof(T);
            while (total < bytes_to_send)
            {
                switch (const auto bytes = ::SSL_write(&m_ssl,
                            reinterpret_cast<const char*>(m_buffer_to.get()) + total,
                            m_buffer_to.size() * sizeof(T));
                        bytes)
                {
                    case -1:
                        throw std::runtime_error{"Failed to read."};
                    case 0:
                        total += bytes;
                        break;
                    default:
                        total += bytes;
                }
            }
            return total / sizeof(T);
        }
    };

    template <typename T>
    struct stream_read_operation
    {
        SSL& m_ssl;
        span<T> m_buffer_from;

        stream_read_operation(SSL& ssl, span<T> buffer)
            : m_ssl(ssl)
            , m_buffer_from(buffer)
        {}

        size_t operator()(const int)
        {
            switch (const auto bytes = ::SSL_read(
                        &m_ssl, reinterpret_cast<char*>(m_buffer_from.get()), m_buffer_from.size() * sizeof(T));
                    bytes)
            {
                case -1:
                    throw std::runtime_error{"Failed to read."};
                case 0:
                    // fall through
                default:
                    return bytes / sizeof(T);
            }
        }
    };

    std::shared_ptr<SSL_CTX> m_context = nullptr;
    std::unique_ptr<SSL, detail::ssl_raw_deleter> m_ssl = nullptr;

    std::string m_certificate;
    std::string m_private_key;

    template <ip_version>
    friend class tls_acceptor;

public:
    tls_connection() = delete;
    tls_connection(const tls_connection&) = delete;
    tls_connection& operator=(const tls_connection&) = delete;

    tls_connection(tls_connection&& rhs) noexcept
        : tcp_connection<IP_VER>{std::move(rhs)}
    {
        m_context = std::move(rhs.m_context);
        m_ssl = std::move(rhs.m_ssl);
        m_certificate = std::move(rhs.m_certificate);
        m_private_key = std::move(rhs.m_private_key);
    }

    tls_connection& operator=(tls_connection&& rhs) noexcept
    {
        // Provide custom move assginment operator to prevent moved object from deleting SSL context pointers
        if (this != &rhs)
        {
            tcp_connection<IP_VER>::operator=(std::move(rhs));

            m_context = std::move(rhs.m_context);
            m_ssl = std::move(rhs.m_ssl);
            m_certificate = std::move(rhs.m_certificate);
            m_private_key = std::move(rhs.m_private_key);
        }
        return *this;
    }

    tls_connection(std::string_view cert_path, std::string_view key_path)
        : tcp_connection<IP_VER>{}
        , m_certificate{detail::read_file(cert_path)}
        , m_private_key{detail::read_file(key_path)}
    {
        detail::init_ssl_system();

        // TODO Change configure function to use the cert and key string not the path
        detail::configure_ssl_ctx(m_context, cert_path, key_path, false);
    }

    tls_connection(std::string_view cert_path, std::string_view key_path, std::string_view conn_addr_str, uint16_t port)
        : tcp_connection<IP_VER>{}
        , m_certificate{detail::read_file(cert_path)}
        , m_private_key{detail::read_file(key_path)}
    {
        detail::init_ssl_system();

        // TODO Change configure function to use the cert and key string not the path
        detail::configure_ssl_ctx(m_context, cert_path, key_path, false);

        const auto conn_addr = endpoint<IP_VER>{conn_addr_str, port, socket_type::stream};
        connect(conn_addr);
    }

    tls_connection(std::string_view cert_path, std::string_view key_path, const endpoint<IP_VER>& conn_addr)
        : tcp_connection<IP_VER>{}
        , m_certificate{detail::read_file(cert_path)}
        , m_private_key{detail::read_file(key_path)}
    {
        detail::init_ssl_system();

        // TODO Change configure function to use the cert and key string not the path
        detail::configure_ssl_ctx(m_context, cert_path, key_path, false);

        connect(conn_addr);
    }

    ~tls_connection() = default;

    void connect(const endpoint<IP_VER>& conn_addr) override
    {
        tcp_connection<IP_VER>::connect(conn_addr);

        SSL* ssl_raw = SSL_new(m_context.get());
        if (ssl_raw == nullptr)
        {
            this->m_connection = tcp_connection<IP_VER>::connection_status::closed;
            throw std::runtime_error{"Failed to instatiate SSL structure."};
        }
        m_ssl.reset(ssl_raw);
        ::SSL_set_fd(m_ssl.get(), this->m_sockfd);

        if (auto ret = SSL_connect(m_ssl.get()); ret != 1)
        {
            this->m_connection = tcp_connection<IP_VER>::connection_status::closed;
            ret = ::SSL_get_error(m_ssl.get(), ret);
            ::ERR_print_errors_fp(stderr);
            throw std::runtime_error{"Failed to connect TLS connection."};
        }
    }

    template <typename T>
    size_t send(span<T> buffer) const
    {
        if (this->m_connection == tcp_connection<IP_VER>::connection_status::closed)
        {
            throw std::runtime_error{"Connection already closed."};
        }

        auto write_op = stream_write_operation<T>(*m_ssl, buffer);
        return write_op(this->m_sockfd);
    }

    template <typename T>
    std::optional<size_t> send(span<T> buffer, const std::chrono::duration<int64_t, std::milli>& timeout) const
    {
        if (this->m_connection == tcp_connection<IP_VER>::connection_status::closed)
        {
            throw std::runtime_error{"Connection already closed."};
        }

        auto mut = std::mutex();
        auto cv = std::condition_variable();
        auto lock = std::unique_lock<std::mutex>{mut};

        auto& exec = detail::executor::instance();
        exec.add(this->m_sockfd,
            detail::event_type::WRITE,
            detail::no_return_completion_handler([&cv](int) { cv.notify_one(); }));

        // Wait for given timeout
        const auto condition_status = cv.wait_for(lock, timeout);
        if (condition_status == std::cv_status::no_timeout)
        {
            return send(buffer);
        }
        else
        {
            exec.remove(this->m_sockfd, detail::event_type::WRITE);
            return std::nullopt;
        }
    }

    template <typename T, typename CALLBACK_TYPE>
    void async_send(span<T> buffer, CALLBACK_TYPE&& callback) const
    {
        auto& exec = detail::executor::instance();
        exec.add(this->m_sockfd,
            detail::event_type::WRITE,
            detail::callback_completion_handler<size_t>(
                stream_write_operation<T>(*m_ssl, buffer), std::forward<CALLBACK_TYPE>(callback)));
    }

    template <typename T>
    std::future<size_t> promised_send(span<T> buffer) const
    {
        auto size_promise = std::promise<size_t>();
        auto size_future = size_promise.get_future();

        auto& exec = detail::executor::instance();
        exec.add(this->m_sockfd,
            detail::event_type::WRITE,
            detail::promise_completion_handler<size_t>(
                stream_write_operation<T>(*m_ssl, buffer), std::move(size_promise)));

        return size_future;
    }

    template <typename T>
    size_t read(span<T> buffer) const
    {
        if (this->m_connection == tcp_connection<IP_VER>::connection_status::closed)
        {
            throw std::runtime_error{"Connection already closed."};
        }

        auto read_op = stream_read_operation<T>(*m_ssl, buffer);
        return read_op(this->m_sockfd);
    }

    template <typename T>
    std::optional<size_t> read(span<T> buffer, const std::chrono::duration<int64_t, std::milli>& timeout) const
    {
        if (this->m_connection == tcp_connection<IP_VER>::connection_status::closed)
        {
            throw std::runtime_error{"Connection already closed."};
        }

        auto mut = std::mutex();
        auto cv = std::condition_variable();
        auto lock = std::unique_lock<std::mutex>{mut};

        auto& exec = detail::executor::instance();
        exec.add(this->m_sockfd,
            detail::event_type::READ,
            detail::no_return_completion_handler([&cv](int) { cv.notify_one(); }));

        // Wait for given timeout
        const auto condition_status = cv.wait_for(lock, timeout);
        if (condition_status == std::cv_status::no_timeout)
        {
            return read(buffer);
        }
        else
        {
            exec.remove(this->m_sockfd, detail::event_type::READ);
            return std::nullopt;
        }
    }

    template <typename T, typename CALLBACK_TYPE>
    void async_read(span<T> buffer, CALLBACK_TYPE&& callback) const
    {
        auto& exec = detail::executor::instance();
        exec.add(this->m_sockfd,
            detail::event_type::READ,
            detail::callback_completion_handler<size_t>(
                stream_read_operation<T>(*m_ssl, buffer), std::forward<CALLBACK_TYPE>(callback)));
    }

    template <typename T>
    std::future<size_t> promised_read(span<T> buffer) const
    {
        auto size_promise = std::promise<size_t>();
        auto size_future = size_promise.get_future();

        auto& exec = detail::executor::instance();
        exec.add(this->m_sockfd,
            detail::event_type::READ,
            detail::promise_completion_handler<size_t>(
                stream_read_operation<T>(*m_ssl, buffer), std::move(size_promise)));

        return size_future;
    }
};

/// Using declarations for shorthand usage of templated tls_connection types
using tls_connection_v4 = tls_connection<ip_version::v4>;
using tls_connection_v6 = tls_connection<ip_version::v6>;

template <ip_version IP_VER>
class tls_acceptor : public tcp_acceptor<IP_VER>
{
private:
    struct stream_accept_operation
    {
        std::shared_ptr<SSL_CTX> m_context;

        stream_accept_operation(std::shared_ptr<SSL_CTX> context)
            : m_context(std::move(context))
        {}

        tls_connection<IP_VER> operator()(const int fd) const
        {
            auto client_addr = endpoint<IP_VER>();
            socklen_t addr_len = client_addr.addr_size;
            if (const int sock = ::accept(fd, &(client_addr.get_addr()), &addr_len);
                sock > 0 && addr_len == client_addr.addr_size)
            {
                return tls_connection<IP_VER>{sock, client_addr, m_context};
            }
            else
            {
                throw std::runtime_error{"Accept operation failed."};
            }
        }
    };

    std::string m_certificate;
    std::string m_private_key;

    std::shared_ptr<SSL_CTX> m_context;
    std::unique_ptr<SSL, detail::ssl_raw_deleter> m_ssl = nullptr;

public:
    tls_acceptor() = delete;
    tls_acceptor(const tls_acceptor&) = delete;
    tls_acceptor operator=(const tls_acceptor&) = delete;

    tls_acceptor(tls_acceptor& rhs) noexcept
        : tcp_acceptor<IP_VER>{std::move(rhs)}
    {
        m_certificate = std::move(rhs.m_certificate);
        m_private_key = std::move(rhs.m_private_key);
        m_context = std::move(rhs.m_context);
        m_ssl = std::move(rhs.m_ssl);
    }

    tls_acceptor& operator=(tls_acceptor&& rhs) noexcept
    {
        // Provide custom move assginment operator to prevent moved object from deleting underlying SSL context
        if (this != &rhs)
        {
            tcp_acceptor<IP_VER>::operator=(std::move(rhs));

            m_certificate = std::move(rhs.m_certificate);
            m_private_key = std::move(rhs.m_private_key);
            m_context = std::move(rhs.m_context);
            m_ssl = std::move(rhs.m_ssl);
        }
        return *this;
    }

    tls_acceptor(std::string_view cert_path, std::string_view key_path)
        : tcp_acceptor<IP_VER>{}
        , m_certificate{detail::read_file(cert_path)}
        , m_private_key{detail::read_file(key_path)}
    {
        detail::init_ssl_system();

        // TODO Change configure function to use the cert and key string not the path
        detail::configure_ssl_ctx(m_context, cert_path, key_path, true);
    }

    tls_acceptor(std::string_view cert_path,
        std::string_view key_path,
        std::string_view bind_addr,
        uint16_t port,
        size_t backlog = 5)
        : tcp_acceptor<IP_VER>{bind_addr, port, backlog}
        , m_certificate{detail::read_file(cert_path)}
        , m_private_key{detail::read_file(key_path)}
    {
        detail::init_ssl_system();

        // TODO Change configure function to use the cert and key string not the path
        detail::configure_ssl_ctx(m_context, cert_path, key_path, true);
    }

    tls_acceptor(std::string_view cert_path,
        std::string_view key_path,
        const endpoint<IP_VER>& bind_addr,
        size_t backlog = 5)
        : tcp_acceptor<IP_VER>{bind_addr, backlog}
        , m_certificate{detail::read_file(cert_path)}
        , m_private_key{detail::read_file(key_path)}
    {
        detail::init_ssl_system();

        // TODO Change configure function to use the cert and key string not the path
        detail::configure_ssl_ctx(m_context, cert_path, key_path, true);
    }

    ~tls_acceptor() = default;

    tls_connection<IP_VER> accept() const
    {
        if (this->m_state == tcp_acceptor<IP_VER>::acceptor_state::non_bound)
            throw std::runtime_error{"Socket not in listening state."};

        auto accept_op = stream_accept_operation(m_context);
        return accept_op(this->m_sockfd);
    }

    std::optional<tls_connection<IP_VER>> accept(const std::chrono::duration<int64_t, std::milli>& timeout) const
    {
        auto cv = std::condition_variable();
        auto mut = std::mutex();
        auto lock = std::unique_lock<std::mutex>{mut};

        auto& exec = detail::executor::instance();
        exec.add(this->m_sockfd,
            detail::event_type::READ,
            detail::no_return_completion_handler([&cv](int) { cv.notify_one(); }));

        // Wait for given timeout
        const auto condition_status = cv.wait_for(lock, timeout);
        if (condition_status == std::cv_status::no_timeout)
        {
            return std::optional<tls_connection<IP_VER>>{accept()};
        }
        else
        {
            exec.remove(this->m_sockfd, detail::event_type::READ);
            return std::nullopt;
        }
    }

    template <typename CALLBACK_TYPE>
    void async_accept(CALLBACK_TYPE&& callback) const
    {
        auto& exec = detail::executor::instance();
        exec.add(this->m_sockfd,
            detail::event_type::READ,
            detail::callback_completion_handler<tls_connection<IP_VER>>(
                stream_accept_operation(m_context), std::forward<CALLBACK_TYPE>(callback)));
    }

    std::future<tls_connection<IP_VER>> promised_accept() const
    {
        auto acc_promise = std::promise<tls_connection<IP_VER>>();
        auto acc_future = acc_promise.get_future();

        auto& exec = detail::executor::instance();
        exec.add(this->m_sockfd,
            detail::event_type::READ,
            detail::promise_completion_handler<tls_connection<IP_VER>>(
                stream_accept_operation(m_context), std::move(acc_promise)));

        return acc_future;
    }
};

/// Using declarations for shorthand usage of templated tls_acceptor types
using tls_acceptor_v4 = tls_acceptor<ip_version::v4>;
using tls_acceptor_v6 = tls_acceptor<ip_version::v6>;

} // namespace net

#endif
