#ifndef SOCKETWRAPPER_NET_TLS_HPP
#define SOCKETWRAPPER_NET_TLS_HPP

#include "tcp.hpp"

#include <memory>
#include <string>
#include <string_view>
#include <mutex>
#include <condition_variable>
#include <stdexcept>

#include <netinet/in.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

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
    ctx = std::shared_ptr<SSL_CTX>(SSL_CTX_new((server) ? TLS_server_method() : TLS_client_method()), [](SSL_CTX* ctx) {
        if(ctx) SSL_CTX_free(ctx);
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

template<ip_version IP_VER>
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

    tls_connection(std::string_view cert_path, std::string_view key_path, std::string_view conn_addr, uint16_t port)
        : tcp_connection<IP_VER> {conn_addr, port},
          m_certificate {detail::read_file(cert_path)},
          m_private_key {detail::read_file(key_path)}
    {
        detail::init_ssl_system();

        // TODO Change configure function to use the cert and key string not the path
        // detail::configure_ssl_ctx(m_ctx, m_certificate, m_private_key, false);
        detail::configure_ssl_ctx(m_context, cert_path, key_path, false);

        if(m_ssl = SSL_new(m_context.get()); m_ssl == nullptr)
            throw std::runtime_error {"Failed to instatiate SSL structure."};
        SSL_set_fd(m_ssl, this->m_sockfd);

        if(auto ret = SSL_connect(m_ssl); ret != 1)
        {
            ret = SSL_get_error(m_ssl, ret);
            ERR_print_errors_fp(stderr);
            throw std::runtime_error {"Failed to connect TLS connection."};
        }
    }

   ~tls_connection()
    {
        if(m_ssl != nullptr)
        {
            SSL_shutdown(m_ssl);
            SSL_free(m_ssl);
        }
    }

private:

    tls_connection(int socketfd, const sockaddr_in& peer_addr, std::shared_ptr<SSL_CTX> context)
        : tcp_connection<IP_VER> {socketfd, peer_addr}, m_context {std::move(context)}
    {
        static_assert(IP_VER == ip_version::v4);

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

    tls_connection(int socketfd, const sockaddr_in6& peer_addr, std::shared_ptr<SSL_CTX> context)
        : tcp_connection<IP_VER> {socketfd, peer_addr}, m_context {std::move(context)}
    {
        static_assert(IP_VER == ip_version::v6);

        if(m_ssl = SSL_new(m_context.get()); m_ssl == nullptr)
            throw std::runtime_error {"Failed to set up SSL."};
        SSL_set_fd(m_ssl, this->m_sockfd);

        if(SSL_accept(m_ssl) != 1)
            throw std::runtime_error {"Failed to accept TLS connection."};
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

    template<ip_version>
    friend class tls_acceptor;
};

/// Using declarations for shorthand usage of templated tls_connection types
using tls_connection_v4 = tls_connection<ip_version::v4>;
using tls_connection_v6 = tls_connection<ip_version::v6>;


template<ip_version IP_VER>
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

    tls_acceptor(std::string_view cert_path, std::string_view key_path, std::string_view bind_addr, uint16_t port, size_t backlog = 5)
        : tcp_acceptor<IP_VER> {bind_addr, port, backlog},
          m_certificate {detail::read_file(cert_path)},
          m_private_key {detail::read_file(key_path)}
    {
        detail::init_ssl_system();

        // TODO Change configure function to use the cert and key string not the path
        // configure_ssl_ctx(m_ctx, m_certificate, m_private_key, true);
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
        if constexpr(IP_VER == ip_version::v4)
        {
            sockaddr_in client {};
            socklen_t len = sizeof(sockaddr_in);
            if(const int sock = ::accept(this->m_sockfd, reinterpret_cast<sockaddr*>(&client), &len); sock >= 0)
                return tls_connection<IP_VER> {sock, client, m_context};
            else
                throw std::runtime_error {"Failed to accept."};
        }
        else if constexpr(IP_VER == ip_version::v6)
        {
            sockaddr_in6 client {};
            socklen_t len = sizeof(sockaddr_in6);
            if(const int sock = ::accept(this->m_sockfd, reinterpret_cast<sockaddr*>(&client), &len); sock >= 0)
                return tls_connection<IP_VER> {sock, client, m_context};
            else
                throw std::runtime_error {"Failed to accept."};
        }
        else
        {
            static_assert(IP_VER == ip_version::v4 || IP_VER == ip_version::v6);
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
