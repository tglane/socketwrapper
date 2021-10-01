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
    if(!initialized)
    {
        SSL_library_init();
        SSL_load_error_strings();
        OpenSSL_add_ssl_algorithms();
        ERR_load_BIO_strings();
        ERR_load_SSL_strings();

        initialized = true;
    }
}

inline void configure_ssl_ctx(std::shared_ptr<SSL_CTX>& ctx, std::string_view cert, std::string_view key, bool server)
{
    ctx = std::shared_ptr<SSL_CTX>(SSL_CTX_new((server) ? TLS_server_method() : TLS_client_method()),
        [](SSL_CTX* ctx)
        {
            if(ctx)
                SSL_CTX_free(ctx);
        });
    if(!ctx)
        throw std::runtime_error {"Failed to create TLS context."};

    SSL_CTX_set_mode(ctx.get(), SSL_MODE_AUTO_RETRY);
    SSL_CTX_set_ecdh_auto(ctx.get(), 1);

    if(SSL_CTX_use_certificate_file(ctx.get(), cert.data(), SSL_FILETYPE_PEM) <= 0)
        throw std::runtime_error {"Failed to set certificate."};
    if(SSL_CTX_use_PrivateKey_file(ctx.get(), key.data(), SSL_FILETYPE_PEM) <= 0)
        throw std::runtime_error {"Failed to set private key."};
}

} // namespace detail

template <ip_version IP_VER>
class tls_connection : public tcp_connection<IP_VER>
{
public:
    tls_connection() = delete;
    tls_connection(const tls_connection&) = delete;
    tls_connection& operator=(const tls_connection&) = delete;

    tls_connection(tls_connection&& rhs) noexcept
        : tcp_connection<IP_VER> {std::move(rhs)}
    {
        m_context = std::move(rhs.m_context);
        m_ssl = rhs.m_ssl;
        m_certificate = std::move(rhs.m_certificate);
        m_private_key = std::move(rhs.m_private_key);

        rhs.m_ssl = nullptr;
    }

    tls_connection& operator=(tls_connection&& rhs) noexcept
    {
        // Provide custom move assginment operator to prevent moved object from deleting SSL context pointers
        if(this != &rhs)
        {
            tcp_connection<IP_VER>::operator=(std::move(rhs));

            m_context = std::move(rhs.m_context);
            m_ssl = rhs.m_ssl;
            m_certificate = std::move(rhs.m_certificate);
            m_private_key = std::move(rhs.m_private_key);

            rhs.m_ssl = nullptr;
        }
        return *this;
    }

    tls_connection(std::string_view cert_path, std::string_view key_path)
        : tcp_connection<IP_VER> {}
        , m_certificate {detail::read_file(cert_path)}
        , m_private_key {detail::read_file(key_path)}
    {
        detail::init_ssl_system();

        // TODO Change configure function to use the cert and key string not the path
        detail::configure_ssl_ctx(m_context, cert_path, key_path, false);
    }

    tls_connection(std::string_view cert_path, std::string_view key_path, std::string_view conn_addr_str, uint16_t port)
        : tcp_connection<IP_VER> {}
        , m_certificate {detail::read_file(cert_path)}
        , m_private_key {detail::read_file(key_path)}
    {
        detail::init_ssl_system();

        // TODO Change configure function to use the cert and key string not the path
        detail::configure_ssl_ctx(m_context, cert_path, key_path, false);

        endpoint<IP_VER> conn_addr {conn_addr_str, port, socket_type::stream};
        connect(conn_addr);
    }

    tls_connection(std::string_view cert_path, std::string_view key_path, const endpoint<IP_VER>& conn_addr)
        : tcp_connection<IP_VER> {}
        , m_certificate {detail::read_file(cert_path)}
        , m_private_key {detail::read_file(key_path)}
    {
        detail::init_ssl_system();

        // TODO Change configure function to use the cert and key string not the path
        detail::configure_ssl_ctx(m_context, cert_path, key_path, false);

        connect(conn_addr);
    }

    ~tls_connection()
    {
        if(m_ssl != nullptr)
        {
            SSL_shutdown(m_ssl);
            SSL_free(m_ssl);
        }
    }

    void connect(const endpoint<IP_VER>& conn_addr) override
    {
        tcp_connection<IP_VER>::connect(conn_addr);

        if(m_ssl = SSL_new(m_context.get()); m_ssl == nullptr)
        {
            this->m_connection = tcp_connection<IP_VER>::connection_status::closed;
            throw std::runtime_error {"Failed to instatiate SSL structure."};
        }
        SSL_set_fd(m_ssl, this->m_sockfd);

        if(auto ret = SSL_connect(m_ssl); ret != 1)
        {
            this->m_connection = tcp_connection<IP_VER>::connection_status::closed;
            ret = SSL_get_error(m_ssl, ret);
            ERR_print_errors_fp(stderr);
            throw std::runtime_error {"Failed to connect TLS connection."};
        }
    }

    template <typename T, typename CALLBACK_TYPE>
    void async_send(span<T> buffer, CALLBACK_TYPE&& callback) const
    {
        detail::async_context::instance().add(this->m_sockfd,
            detail::async_context::WRITE,
            detail::stream_write_callback<tls_connection<IP_VER>, T> {
                this, buffer, std::forward<CALLBACK_TYPE>(callback)});
    }

    template <typename T>
    std::future<size_t> promised_send(span<T> buffer) const
    {
        std::promise<size_t> size_promise;
        std::future<size_t> size_future = size_promise.get_future();

        detail::async_context::instance().add(this->m_sockfd,
            detail::async_context::WRITE,
            detail::stream_promised_write_callback<tls_connection<IP_VER>, T> {this, buffer, std::move(size_promise)});

        return size_future;
    }

    template <typename T, typename CALLBACK_TYPE>
    void async_read(span<T> buffer, CALLBACK_TYPE&& callback) const
    {
        detail::async_context::instance().add(this->m_sockfd,
            detail::async_context::READ,
            detail::stream_read_callback<tls_connection<IP_VER>, T> {
                this, buffer, std::forward<CALLBACK_TYPE>(callback)});
    }

    template <typename T>
    std::future<size_t> promised_read(span<T> buffer) const
    {
        std::promise<size_t> size_promise;
        std::future<size_t> size_future = size_promise.get_future();

        detail::async_context::instance().add(this->m_sockfd,
            detail::async_context::READ,
            detail::stream_promised_read_callback<tls_connection<IP_VER>, T> {this, buffer, std::move(size_promise)});

        return size_future;
    }

private:
    tls_connection(int socketfd, const endpoint<IP_VER>& peer_addr, std::shared_ptr<SSL_CTX> context)
        : tcp_connection<IP_VER> {socketfd, peer_addr}
        , m_context {std::move(context)}
    {
        if(m_ssl = SSL_new(m_context.get()); m_ssl == nullptr)
            throw std::runtime_error {"Failed to instatiate SSL structure."};
        SSL_set_fd(m_ssl, this->m_sockfd);

        if(const auto ret = SSL_accept(m_ssl); ret != 1)
        {
            SSL_get_error(m_ssl, ret);
            ERR_print_errors_fp(stderr);
            throw std::runtime_error {"Failed to accept TLS connection."};
        }
    }

    int read_from_socket(char* const buffer_to, const size_t bytes_to_read) const override
    {
        return SSL_read(m_ssl, buffer_to, bytes_to_read);
    }

    int write_to_socket(const char* buffer_from, const size_t bytes_to_write) const override
    {
        return SSL_write(m_ssl, buffer_from, bytes_to_write);
    }

    std::shared_ptr<SSL_CTX> m_context;
    SSL* m_ssl;

    std::string m_certificate;
    std::string m_private_key;

    template <ip_version>
    friend class tls_acceptor;
};

/// Using declarations for shorthand usage of templated tls_connection types
using tls_connection_v4 = tls_connection<ip_version::v4>;
using tls_connection_v6 = tls_connection<ip_version::v6>;

template <ip_version IP_VER>
class tls_acceptor : public tcp_acceptor<IP_VER>
{
public:
    tls_acceptor() = delete;
    tls_acceptor(const tls_acceptor&) = delete;
    tls_acceptor operator=(const tls_acceptor&) = delete;

    tls_acceptor(tls_acceptor& rhs) noexcept
        : tcp_acceptor<IP_VER> {std::move(rhs)}
    {
        m_certificate = std::move(rhs.m_certificate);
        m_private_key = std::move(rhs.m_private_key);
        m_context = std::move(rhs.m_context);
        m_ssl = rhs.m_ssl;

        rhs.m_ssl = nullptr;
    }

    tls_acceptor& operator=(tls_acceptor&& rhs) noexcept
    {
        // Provide custom move assginment operator to prevent moved object from deleting underlying SSL context
        if(this != &rhs)
        {
            tcp_acceptor<IP_VER>::operator=(std::move(rhs));

            m_certificate = std::move(rhs.m_certificate);
            m_private_key = std::move(rhs.m_private_key);
            m_context = std::move(rhs.m_context);
            m_ssl = rhs.m_ssl;

            rhs.m_ssl = nullptr;
        }
        return *this;
    }

    tls_acceptor(std::string_view cert_path, std::string_view key_path)
        : tcp_acceptor<IP_VER> {}
        , m_certificate {detail::read_file(cert_path)}
        , m_private_key {detail::read_file(key_path)}
    {
        detail::init_ssl_system();

        // TODO Change configure function to use the cert and key string not the path
        detail::configure_ssl_ctx(m_context, cert_path, key_path, true);
    }

    tls_acceptor(std::string_view cert_path, std::string_view key_path, std::string_view bind_addr, uint16_t port,
        size_t backlog = 5)
        : tcp_acceptor<IP_VER> {bind_addr, port, backlog}
        , m_certificate {detail::read_file(cert_path)}
        , m_private_key {detail::read_file(key_path)}
    {
        detail::init_ssl_system();

        // TODO Change configure function to use the cert and key string not the path
        detail::configure_ssl_ctx(m_context, cert_path, key_path, true);
    }

    tls_acceptor(
        std::string_view cert_path, std::string_view key_path, const endpoint<IP_VER>& bind_addr, size_t backlog = 5)
        : tcp_acceptor<IP_VER> {bind_addr, backlog}
        , m_certificate {detail::read_file(cert_path)}
        , m_private_key {detail::read_file(key_path)}
    {
        detail::init_ssl_system();

        // TODO Change configure function to use the cert and key string not the path
        detail::configure_ssl_ctx(m_context, cert_path, key_path, true);
    }

    ~tls_acceptor()
    {
        if(m_ssl != nullptr)
        {
            SSL_shutdown(m_ssl);
            SSL_free(m_ssl);
        }
    }

    tls_connection<IP_VER> accept() const
    {
        if(this->m_state == tcp_acceptor<IP_VER>::acceptor_state::non_bound)
            throw std::runtime_error {"Socket not in listening state."};

        endpoint<IP_VER> client_addr;
        socklen_t addr_len = client_addr.addr_size;
        if(const int sock = ::accept(this->m_sockfd, &(client_addr.get_addr()), &addr_len);
            sock > 0 && addr_len == client_addr.addr_size)
        {
            return tls_connection<IP_VER> {sock, client_addr, m_context};
        }
        else
        {
            throw std::runtime_error {"Accept operation failed."};
        }
    }

    std::optional<tls_connection<IP_VER>> accept(const std::chrono::duration<int64_t, std::milli>& delay) const
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
            return std::optional<tls_connection<IP_VER>> {accept()};
        else
            return std::nullopt;
    }

    template <typename CALLBACK_TYPE>
    void async_accept(CALLBACK_TYPE&& callback) const
    {
        detail::async_context::instance().add(this->m_sockfd,
            detail::async_context::READ,
            detail::stream_accept_callback<tls_acceptor<IP_VER>> {this, std::forward<CALLBACK_TYPE>(callback)});
    }

    std::future<tls_connection<IP_VER>> promised_accept() const
    {
        std::promise<tls_connection<IP_VER>> acc_promise;
        std::future<tls_connection<IP_VER>> acc_future = acc_promise.get_future();

        detail::async_context::instance().add(this->m_sockfd,
            detail::async_context::READ,
            detail::stream_promised_accept_callback<tls_acceptor<IP_VER>> {this, std::move(acc_promise)});

        return acc_future;
    }

private:
    std::string m_certificate;
    std::string m_private_key;

    std::shared_ptr<SSL_CTX> m_context;
    SSL* m_ssl = nullptr;
};

/// Using declarations for shorthand usage of templated tls_acceptor types
using tls_acceptor_v4 = tls_acceptor<ip_version::v4>;
using tls_acceptor_v6 = tls_acceptor<ip_version::v6>;

} // namespace net

#endif
