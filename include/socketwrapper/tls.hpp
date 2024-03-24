#ifndef SOCKETWRAPPER_NET_TLS_HPP
#define SOCKETWRAPPER_NET_TLS_HPP

#include <condition_variable>
#include <memory>
#include <mutex>
#include <stdexcept>
#include <string>
#include <string_view>

#include <netinet/in.h>
#include <openssl/err.h>
#include <openssl/ssl.h>

#include "tcp.hpp"
#if __cplusplus >= 202002L
#include "awaitable.hpp"
#endif

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

template <ip_version ip_ver_v>
class tls_connection : public tcp_connection<ip_ver_v>
{
    tls_connection(int socketfd, const endpoint<ip_ver_v>& peer_addr, std::shared_ptr<SSL_CTX> context)
        : tcp_connection<ip_ver_v>{socketfd, peer_addr}
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

    template <typename data_type>
    struct stream_write_operation
    {
        SSL& m_ssl;
        span<data_type> m_buffer_to;

        stream_write_operation(SSL& ssl, span<data_type> buffer)
            : m_ssl(ssl)
            , m_buffer_to(buffer)
        {}

        size_t operator()(const int) const
        {
            size_t total = 0;
            const size_t bytes_to_send = m_buffer_to.size() * sizeof(data_type);
            while (total < bytes_to_send)
            {
                switch (const auto bytes = ::SSL_write(&m_ssl,
                            reinterpret_cast<const char*>(m_buffer_to.get()) + total,
                            m_buffer_to.size() * sizeof(data_type));
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
            return total / sizeof(data_type);
        }
    };

    template <typename data_type>
    struct stream_read_operation
    {
        SSL& m_ssl;
        span<data_type> m_buffer_from;

        stream_read_operation(SSL& ssl, span<data_type> buffer)
            : m_ssl(ssl)
            , m_buffer_from(buffer)
        {}

        size_t operator()(const int)
        {
            switch (const auto bytes = ::SSL_read(
                        &m_ssl, reinterpret_cast<char*>(m_buffer_from.get()), m_buffer_from.size() * sizeof(data_type));
                    bytes)
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
        : tcp_connection<ip_ver_v>{std::move(rhs)}
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
            tcp_connection<ip_ver_v>::operator=(std::move(rhs));

            m_context = std::move(rhs.m_context);
            m_ssl = std::move(rhs.m_ssl);
            m_certificate = std::move(rhs.m_certificate);
            m_private_key = std::move(rhs.m_private_key);
        }
        return *this;
    }

    tls_connection(std::string_view cert_path, std::string_view key_path)
        : tcp_connection<ip_ver_v>{}
        , m_certificate{detail::read_file(cert_path)}
        , m_private_key{detail::read_file(key_path)}
    {
        detail::init_ssl_system();

        // TODO Change configure function to use the cert and key string not the path
        detail::configure_ssl_ctx(m_context, cert_path, key_path, false);
    }

    tls_connection(std::string_view cert_path, std::string_view key_path, const endpoint<ip_ver_v>& conn_addr)
        : tcp_connection<ip_ver_v>{}
        , m_certificate{detail::read_file(cert_path)}
        , m_private_key{detail::read_file(key_path)}
    {
        detail::init_ssl_system();

        // TODO Change configure function to use the cert and key string not the path
        detail::configure_ssl_ctx(m_context, cert_path, key_path, false);

        connect(conn_addr);
    }

    ~tls_connection() = default;

    void connect(const endpoint<ip_ver_v>& conn_addr) override
    {
        tcp_connection<ip_ver_v>::connect(conn_addr);

        SSL* ssl_raw = SSL_new(m_context.get());
        if (ssl_raw == nullptr)
        {
            this->m_connection = tcp_connection<ip_ver_v>::connection_status::closed;
            throw std::runtime_error{"Failed to instatiate SSL structure."};
        }
        m_ssl.reset(ssl_raw);
        ::SSL_set_fd(m_ssl.get(), this->m_sockfd);

        if (auto ret = SSL_connect(m_ssl.get()); ret != 1)
        {
            this->m_connection = tcp_connection<ip_ver_v>::connection_status::closed;
            ret = ::SSL_get_error(m_ssl.get(), ret);
            ::ERR_print_errors_fp(stderr);
            throw std::runtime_error{"Failed to connect TLS connection."};
        }
    }

    template <typename data_type>
    size_t send(span<data_type> buffer) const
    {
        if (this->m_connection == tcp_connection<ip_ver_v>::connection_status::closed)
        {
            throw std::runtime_error{"Connection already closed."};
        }

        auto write_op = stream_write_operation<data_type>(*m_ssl, buffer);
        return write_op(this->m_sockfd);
    }

    template <typename data_type>
    std::optional<size_t> send(span<data_type> buffer, const std::chrono::duration<int64_t, std::milli>& timeout) const
    {
        if (this->m_connection == tcp_connection<ip_ver_v>::connection_status::closed)
        {
            throw std::runtime_error{"Connection already closed."};
        }

        auto mut = std::mutex();
        auto cv = std::condition_variable();
        auto lock = std::unique_lock<std::mutex>{mut};

        auto& exec = detail::event_loop::instance();
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

    template <typename data_type, typename callback_type>
    void async_send(span<data_type> buffer, callback_type&& callback) const
    {
        auto& exec = detail::event_loop::instance();
        exec.add(this->m_sockfd,
            detail::event_type::WRITE,
            detail::callback_completion_handler<size_t>(
                stream_write_operation<data_type>(*m_ssl, buffer), std::forward<callback_type>(callback)));
    }

#if __cplusplus >= 202002L
    template <typename data_type>
    op_awaitable<size_t, stream_write_operation<data_type>> async_send(span<data_type> buffer) const
    {
        return op_awaitable<size_t, stream_write_operation<data_type>>(
            this->m_sockfd, stream_write_operation<data_type>(buffer), detail::event_type::WRITE);
    }
#endif

    template <typename data_type>
    std::future<size_t> promised_send(span<data_type> buffer) const
    {
        auto size_promise = std::promise<size_t>();
        auto size_future = size_promise.get_future();

        auto& exec = detail::event_loop::instance();
        exec.add(this->m_sockfd,
            detail::event_type::WRITE,
            detail::promise_completion_handler<size_t>(
                stream_write_operation<data_type>(*m_ssl, buffer), std::move(size_promise)));

        return size_future;
    }

    template <typename data_type>
    size_t read(span<data_type> buffer) const
    {
        if (this->m_connection == tcp_connection<ip_ver_v>::connection_status::closed)
        {
            throw std::runtime_error{"Connection already closed."};
        }

        auto read_op = stream_read_operation<data_type>(*m_ssl, buffer);
        return read_op(this->m_sockfd);
    }

    template <typename data_type>
    std::optional<size_t> read(span<data_type> buffer, const std::chrono::duration<int64_t, std::milli>& timeout) const
    {
        if (this->m_connection == tcp_connection<ip_ver_v>::connection_status::closed)
        {
            throw std::runtime_error{"Connection already closed."};
        }

        auto mut = std::mutex();
        auto cv = std::condition_variable();
        auto lock = std::unique_lock<std::mutex>{mut};

        auto& exec = detail::event_loop::instance();
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

    template <typename data_type, typename callback_type>
    void async_read(span<data_type> buffer, callback_type&& callback) const
    {
        auto& exec = detail::event_loop::instance();
        exec.add(this->m_sockfd,
            detail::event_type::READ,
            detail::callback_completion_handler<size_t>(
                stream_read_operation<data_type>(*m_ssl, buffer), std::forward<callback_type>(callback)));
    }

#if __cplusplus >= 202002L
    template <typename data_type>
    op_awaitable<size_t, stream_read_operation<data_type>> async_read(span<data_type> buffer) const
    {
        return op_awaitable<size_t, stream_read_operation<data_type>>(
            this->m_sockfd, stream_read_operation<data_type>(buffer), detail::event_type::READ);
    }
#endif

    template <typename data_type>
    std::future<size_t> promised_read(span<data_type> buffer) const
    {
        auto size_promise = std::promise<size_t>();
        auto size_future = size_promise.get_future();

        auto& exec = detail::event_loop::instance();
        exec.add(this->m_sockfd,
            detail::event_type::READ,
            detail::promise_completion_handler<size_t>(
                stream_read_operation<data_type>(*m_ssl, buffer), std::move(size_promise)));

        return size_future;
    }
};

/// Using declarations for shorthand usage of templated tls_connection types
using tls_connection_v4 = tls_connection<ip_version::v4>;
using tls_connection_v6 = tls_connection<ip_version::v6>;

template <ip_version ip_ver_v>
class tls_acceptor : public tcp_acceptor<ip_ver_v>
{
private:
    struct stream_accept_operation
    {
        std::shared_ptr<SSL_CTX> m_context;

        stream_accept_operation(std::shared_ptr<SSL_CTX> context)
            : m_context(std::move(context))
        {}

        tls_connection<ip_ver_v> operator()(const int fd) const
        {
            auto client_addr = endpoint<ip_ver_v>();
            socklen_t addr_len = client_addr.addr_size;
            if (const int sock = ::accept(fd, &(client_addr.get_addr()), &addr_len);
                sock > 0 && addr_len == client_addr.addr_size)
            {
                return tls_connection<ip_ver_v>{sock, client_addr, m_context};
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
        : tcp_acceptor<ip_ver_v>{std::move(rhs)}
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
            tcp_acceptor<ip_ver_v>::operator=(std::move(rhs));

            m_certificate = std::move(rhs.m_certificate);
            m_private_key = std::move(rhs.m_private_key);
            m_context = std::move(rhs.m_context);
            m_ssl = std::move(rhs.m_ssl);
        }
        return *this;
    }

    tls_acceptor(std::string_view cert_path, std::string_view key_path)
        : tcp_acceptor<ip_ver_v>{}
        , m_certificate{detail::read_file(cert_path)}
        , m_private_key{detail::read_file(key_path)}
    {
        detail::init_ssl_system();

        // TODO Change configure function to use the cert and key string not the path
        detail::configure_ssl_ctx(m_context, cert_path, key_path, true);
    }

    tls_acceptor(std::string_view cert_path,
        std::string_view key_path,
        const endpoint<ip_ver_v>& bind_addr,
        size_t backlog = 5)
        : tcp_acceptor<ip_ver_v>{bind_addr, backlog}
        , m_certificate{detail::read_file(cert_path)}
        , m_private_key{detail::read_file(key_path)}
    {
        detail::init_ssl_system();

        // TODO Change configure function to use the cert and key string not the path
        detail::configure_ssl_ctx(m_context, cert_path, key_path, true);
    }

    ~tls_acceptor() = default;

    tls_connection<ip_ver_v> accept() const
    {
        if (this->m_state == tcp_acceptor<ip_ver_v>::acceptor_state::non_bound)
            throw std::runtime_error{"Socket not in listening state."};

        auto accept_op = stream_accept_operation(m_context);
        return accept_op(this->m_sockfd);
    }

    std::optional<tls_connection<ip_ver_v>> accept(const std::chrono::duration<int64_t, std::milli>& timeout) const
    {
        auto cv = std::condition_variable();
        auto mut = std::mutex();
        auto lock = std::unique_lock<std::mutex>{mut};

        auto& exec = detail::event_loop::instance();
        exec.add(this->m_sockfd,
            detail::event_type::READ,
            detail::no_return_completion_handler([&cv](int) { cv.notify_one(); }));

        // Wait for given timeout
        const auto condition_status = cv.wait_for(lock, timeout);
        if (condition_status == std::cv_status::no_timeout)
        {
            return std::optional<tls_connection<ip_ver_v>>{accept()};
        }
        else
        {
            exec.remove(this->m_sockfd, detail::event_type::READ);
            return std::nullopt;
        }
    }

    template <typename callback_type>
    void async_accept(callback_type&& callback) const
    {
        auto& exec = detail::event_loop::instance();
        exec.add(this->m_sockfd,
            detail::event_type::READ,
            detail::callback_completion_handler<tls_connection<ip_ver_v>>(
                stream_accept_operation(m_context), std::forward<callback_type>(callback)));
    }

#if __cplusplus >= 202002L
    op_awaitable<tls_connection<ip_ver_v>, stream_accept_operation> async_accept() const
    {
        return op_awaitable<tls_connection<ip_ver_v>, stream_accept_operation>(
            this->m_sockfd, stream_accept_operation(), detail::event_type::READ);
    }
#endif

    std::future<tls_connection<ip_ver_v>> promised_accept() const
    {
        auto acc_promise = std::promise<tls_connection<ip_ver_v>>();
        auto acc_future = acc_promise.get_future();

        auto& exec = detail::event_loop::instance();
        exec.add(this->m_sockfd,
            detail::event_type::READ,
            detail::promise_completion_handler<tls_connection<ip_ver_v>>(
                stream_accept_operation(m_context), std::move(acc_promise)));

        return acc_future;
    }
};

/// Using declarations for shorthand usage of templated tls_acceptor types
using tls_acceptor_v4 = tls_acceptor<ip_version::v4>;
using tls_acceptor_v6 = tls_acceptor<ip_version::v6>;

} // namespace net

#endif
