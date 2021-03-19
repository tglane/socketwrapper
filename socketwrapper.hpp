/**
 * Socketwrapper Socket Library
 * Timo Glane
 * 2021
 */

#ifndef SOCKETWRAPPER_HPP
#define SOCKETWRAPPER_HPP

#define TLS_ENABLED

#include <memory>
#include <string>
#include <string_view>
#include <fstream>
#include <array>
#include <vector>
#include <variant>
#include <stdexcept>
#include <charconv>
#include <utility>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>

#ifdef TLS_ENABLED
    // Include ssl header when needed
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <csignal>
#endif

namespace net {

enum class ip_version : uint8_t
{
    v4 = AF_INET,
    v6 = AF_INET6
};

enum class socket_type : uint8_t
{
    stream = SOCK_STREAM,
    datagram = SOCK_DGRAM
};

// Struct containing connection data including a string representation of peers ip address and port
struct connection_tuple
{
    std::string addr;
    uint16_t port;
};

// Generic non-owning buffer type inspirated by golangs slices
template<typename T>
class span
{
public:
    span() = delete;
    span(const span&) noexcept = default;
    span& operator=(const span&) noexcept = default;
    span(span&&) noexcept = default;
    span& operator=(span&&) noexcept = default;
    ~span() noexcept = default;

    span(T* start, size_t length) noexcept
        : m_start {start}, m_size {length}
    {}

    span(T* start, T* end) noexcept
        : m_start {start}, m_size {static_cast<size_t>(std::distance(start, end) + 1)}
    {}

    template<size_t S>
    span(T (&buffer)[S]) noexcept
        : m_start {buffer}, m_size {S}
    {}

    template<typename ITER>
    span(ITER start, ITER end) noexcept
        : m_start {&(*start)}, m_size {static_cast<size_t>(std::distance(&(*start), &(*end)))}
    {}

    template<typename CONTAINER>
    span(CONTAINER&& con) noexcept
        : m_start {con.data()}, m_size {con.size()}
    {}

    T* get() const { return m_start; }

    constexpr size_t size() const { return m_size; }

    constexpr bool empty() const { return m_size > 0; }

    constexpr T& operator[](size_t index) { return m_start[index]; }
    constexpr const T& operator[](size_t index) const { return m_start[index]; }

    constexpr T* begin() const { return m_start; }
    constexpr T* end() const { return &(m_start[m_size]); }

    constexpr T& front() const { return m_start[0]; }
    constexpr T& back() const { return m_start[m_size - 1]; }

private:
    T* m_start;
    size_t m_size;
};

// Deduction guides for class span
template<typename ITER>
span(ITER, ITER) -> span<typename std::iterator_traits<ITER>::value_type>;

template<typename CONTAINER>
span(const CONTAINER&) -> span<typename std::remove_reference<decltype(std::declval<CONTAINER>().front())>::type>;

// Begin and end functions for span class
template<typename T>
inline constexpr T* begin(const span<T>& buffer) noexcept { return buffer.begin(); }
template<typename T>
inline constexpr T* end(const span<T>& buffer) noexcept { return buffer.end(); }

namespace utility {

    template<ip_version IP_VER>
    inline int resolve_hostname(std::string_view host_name,
                        uint16_t port,
                        socket_type type,
                        std::variant<sockaddr_in, sockaddr_in6>& addr_out)
    {
        int ret;

        addrinfo hints {};
        hints.ai_family = static_cast<uint8_t>(IP_VER);
        hints.ai_socktype = static_cast<uint8_t>(type);
        
        std::array<char, 6> port_buffer {0, 0, 0, 0, 0, '\0'};
        auto [end_ptr, ec] = std::to_chars(port_buffer.begin(), port_buffer.end(), port);
        if(ec != std::errc())
            return -1;

        std::string_view port_str {port_buffer.begin(), std::distance(port_buffer.begin(), port_buffer.end())};

        std::unique_ptr<addrinfo, decltype(&::freeaddrinfo)> resultlist_owner {nullptr, &::freeaddrinfo};
        addrinfo* tmp_resultlist = resultlist_owner.get();
        ret = ::getaddrinfo(host_name.data(), port_str.data(), &hints, &tmp_resultlist);
        resultlist_owner.reset(tmp_resultlist);

        if(ret == 0)
        {
            if constexpr(IP_VER == ip_version::v4) {
                addr_out = *reinterpret_cast<sockaddr_in*>(resultlist_owner->ai_addr);
            }
            else if constexpr(IP_VER == ip_version::v6)
                addr_out = *reinterpret_cast<sockaddr_in6*>(resultlist_owner->ai_addr);
            else
                static_assert(IP_VER == ip_version::v4 || IP_VER == ip_version::v6);
        }

        return ret;
    }

    template<ip_version IP_VER>
    inline connection_tuple resolve_addrinfo(sockaddr* addr_in)
    {
        // TODO
        connection_tuple peer {};
        if constexpr(IP_VER == ip_version::v4)
        {
            peer.addr.resize(INET_ADDRSTRLEN);
            std::string port_str; // Use string instead of array here because std::stoi creates a string anyway
            port_str.resize(6);

            if(inet_ntop(AF_INET, &(reinterpret_cast<sockaddr_in*>(addr_in)->sin_addr), peer.addr.data(), peer.addr.capacity()) == nullptr)
                throw std::runtime_error {"Failed to resolve addrinfo."};
            peer.port = ntohs(reinterpret_cast<sockaddr_in*>(addr_in)->sin_port);

            return peer;
        }
        else if constexpr(IP_VER == ip_version::v6)
        {
            peer.addr.resize(INET6_ADDRSTRLEN);
            std::string port_str; // Use string instead of array here because std::stoi creates a string anyway
            port_str.resize(6);

            if(inet_ntop(AF_INET, &(reinterpret_cast<sockaddr_in6*>(addr_in)->sin6_addr), peer.addr.data(), peer.addr.capacity()) == nullptr)
                throw std::runtime_error {"Failed to resolve addrinfo."};
            peer.port = ntohs(reinterpret_cast<sockaddr_in6*>(addr_in)->sin6_port);

            return peer;
        }
        else
        {
            static_assert(IP_VER == ip_version::v4 || IP_VER == ip_version::v6);
        }
    }

    inline std::string read_file(std::string_view path)
    {
        std::ifstream ifs {path.data()};
        std::string out;

        // Reserve memory up front
        ifs.seekg(0, std::ios::end);
        out.reserve(ifs.tellg());
        ifs.seekg(0, std::ios::beg);

        out.assign({std::istreambuf_iterator<char>{ifs}, std::istreambuf_iterator<char>{}});
        return out;
    }

#ifdef TLS_ENABLED

    inline void init_ssl_system()
    {
        static bool initialized = false;
        if(!initialized)
        {
            signal(SIGPIPE, SIG_IGN);

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

#endif

} // namespace utility

template<ip_version IP_VER>
class tcp_connection
{
protected:
    enum class connection_status : uint8_t
    {
        closed,
        connected
    };

public:

    tcp_connection() = delete;
    tcp_connection(const tcp_connection&) = delete;
    tcp_connection& operator=(const tcp_connection&) = delete;
    tcp_connection(tcp_connection&&) = default;
    tcp_connection& operator=(tcp_connection&&) = default;

    tcp_connection(std::string_view conn_addr, uint16_t port_to)
        : m_sockfd {::socket(static_cast<uint8_t>(IP_VER), static_cast<uint8_t>(socket_type::stream), 0)}, m_family {IP_VER}, m_connection {connection_status::closed}
    {
        if(m_sockfd == -1)
            throw std::runtime_error {"Failed to created socket."};

        int reuse = 1;
        if(::setsockopt(m_sockfd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse)) < 0) 
            throw std::runtime_error {"Failed to set address reusable."};
    
#ifdef SO_REUSEPORT
        if(::setsockopt(m_sockfd, SOL_SOCKET, SO_REUSEPORT, &reuse, sizeof(reuse)) < 0) 
            throw std::runtime_error {"Failed to set port reusable."};
#endif

        if(utility::resolve_hostname<IP_VER>(conn_addr, port_to, socket_type::stream, m_peer) != 0)
            throw std::runtime_error {"Failed to resolve hostname."};

        if constexpr(IP_VER == ip_version::v4)
        {
            auto& ref = std::get<sockaddr_in>(m_peer);
            if(auto res = ::connect(m_sockfd, reinterpret_cast<sockaddr*>(&ref), sizeof(sockaddr_in)); res != 0)
                throw std::runtime_error {"Failed to connect."};
            m_connection = connection_status::connected;
        }
        else if constexpr(IP_VER == ip_version::v6)
        {
            auto& ref = std::get<sockaddr_in6>(m_peer);
            if(auto res = ::connect(m_sockfd, reinterpret_cast<sockaddr*>(&ref), sizeof(sockaddr_in)); res != 0)
                throw std::runtime_error {"Failed to connect."};
            m_connection = connection_status::connected;
        }
        else
        {
            static_assert(IP_VER == ip_version::v4 || IP_VER == ip_version::v6);
        }
    }

    ~tcp_connection()
    {
        ::close(m_sockfd);
    }

    template<typename T>
    void send(const std::vector<T>& buffer) const
    {
        if(m_connection == connection_status::closed)
            throw std::runtime_error {"Connection already closed."};

        if(write_to_socket(buffer.data(), buffer.size()) < 0)
            throw std::runtime_error {"Failed to send."};
    }

    template<typename T>
    void send(const std::vector<T>& buffer, size_t size) const
    {
        if(m_connection == connection_status::closed)
            throw std::runtime_error {"Connection already closed."};

        if(write_to_socket(buffer.data(), size) < 0)
            throw std::runtime_error {"Failed to send."};
    }

    template<typename T, size_t SIZE>
    void send(const std::array<T, SIZE>& buffer, size_t size = SIZE) const
    {
        if(m_connection == connection_status::closed)
            throw std::runtime_error {"Connection already closed."};

        if(write_to_socket(buffer.data(), size) < 0)
            throw std::runtime_error {"Failed to send."};
    }

    void send(std::string_view buffer) const
    {
        if(m_connection == connection_status::closed)
            throw std::runtime_error {"Connection already closed."};

        if(write_to_socket(buffer.data(), buffer.size()) < 0)
            throw std::runtime_error {"Failed to send."};
    }

    template<typename T>
    std::vector<T> read(size_t size) const
    {
        if(m_connection == connection_status::closed)
            throw std::runtime_error {"Connection already closed."};

        std::vector<T> buffer;
        buffer.resize(size);

        switch(auto bytes = read_from_socket(buffer.data(), buffer.size() * sizeof(T)); bytes)
        {
            case -1:
                throw std::runtime_error {"Failed to read."};
            case 0:
                m_connection = connection_status::closed;
                // fall through
            default:
                buffer.resize(bytes);
                return buffer;
        }
    }

    template<typename T, size_t SIZE>
    std::array<T, SIZE> read() const
    {
        if(m_connection == connection_status::closed)
            throw std::runtime_error {"Connection already closed."};

        std::array<T, SIZE> buffer;

        switch(auto bytes = read_from_socket(buffer.data(), SIZE * sizeof(T)); bytes)
        {
            case -1:
                throw std::runtime_error {"Failed to read."};
            case 0:
                m_connection = connection_status::closed;
                // fall through
            default:
                return buffer;
        }
    }

    template<typename T>
    size_t read(std::vector<T>& buffer_to_append, size_t size_to_append) const
    {
        if(m_connection == connection_status::closed)
            throw std::runtime_error {"Connection already closed."};

        auto old_size = buffer_to_append.size();
        if(buffer_to_append.capacity() - old_size < size_to_append)
            buffer_to_append.resize(old_size + size_to_append);

        switch(auto bytes = read_from_socket(buffer_to_append.data() + old_size, size_to_append * sizeof(T)); bytes)
        {
            case -1:
                throw std::runtime_error {"Failed to read."};
            case 0:
                m_connection = connection_status::closed;
                // fall through
            default:
                return bytes;
        }
    }

    template<typename T, size_t SIZE>
    size_t read(std::array<T, SIZE>& buffer_to_append, size_t size_to_append) const
    {
        if(m_connection == connection_status::closed)
            throw std::runtime_error {"Connection already closed."};

        static_assert(buffer_to_append.size() <= size_to_append);

        switch(auto bytes = read_from_socket(buffer_to_append.data(), size_to_append * sizeof(T)); bytes)
        {
            case -1:
                throw std::runtime_error {"Failed to read."};
            case 0:
                m_connection = connection_status::closed;
                // fall through
            default:
                return bytes;
        }
    }

    template<typename T>
    size_t read(T* buffer_to_append, size_t size_to_append) const
    {
        if(m_connection == connection_status::closed)
            throw std::runtime_error {"Connection already closed."};


        switch(auto bytes = read_from_socket(reinterpret_cast<char*>(buffer_to_append), size_to_append * sizeof(T)); bytes)
        {
            case -1:
                throw std::runtime_error {"Failed to read."};
            case 0:
                m_connection = connection_status::closed;
                // fall through
            default:
                return bytes;
        }
    }

    template<typename T>
    void send(span<T>&& buffer) const
    {
        // TODO
    }

    template<typename T>
    size_t read(const span<T>& buffer) const
    {
        // TODO
        return 0;
    }

    int get() const
    {
        return m_sockfd;
    }

protected:

    tcp_connection(int socket_fd, const sockaddr_in& peer_addr)
        : m_sockfd {socket_fd}, m_family {ip_version::v4}, m_peer {peer_addr}, m_connection {connection_status::connected}
    {}

    tcp_connection(int socket_fd, const sockaddr_in6& peer_addr)
        : m_sockfd {socket_fd}, m_family {ip_version::v6}, m_peer {peer_addr}, m_connection {connection_status::connected}
    {}

    virtual int read_from_socket(char* const buffer_to, size_t bytes_to_read) const
    {
        return ::recv(m_sockfd, buffer_to, bytes_to_read, 0);
    }

    virtual int write_to_socket(const char* buffer_from, size_t bytes_to_write) const
    {
        return ::send(m_sockfd, buffer_from, bytes_to_write, 0);
    }

    int m_sockfd;

    ip_version m_family;

    std::variant<sockaddr_in, sockaddr_in6> m_peer = {};

    mutable connection_status m_connection;

    template<ip_version>
    friend class tcp_acceptor;

};

template<ip_version IP_VER>
class tcp_acceptor
{
public:

    tcp_acceptor() = delete;
    tcp_acceptor(const tcp_acceptor&) = delete;
    tcp_acceptor& operator=(const tcp_acceptor&) = delete;
    tcp_acceptor(tcp_acceptor&&) = default;
    tcp_acceptor& operator=(tcp_acceptor&&) = default;

    tcp_acceptor(std::string_view bind_addr, uint16_t port, size_t backlog = 5)
        : m_sockfd {::socket(static_cast<uint8_t>(IP_VER), static_cast<uint8_t>(socket_type::stream), 0)}, m_family {IP_VER}
    {
        if(m_sockfd == -1)
            throw std::runtime_error {"Failed to create socket."};
     
        int reuse = 1;
        if(::setsockopt(m_sockfd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(int)) < 0) 
            throw std::runtime_error {"Failed to set address resusable."};
    
#ifdef SO_REUSEPORT
        if(::setsockopt(m_sockfd, SOL_SOCKET, SO_REUSEPORT, &reuse, sizeof(int)) < 0) 
            throw std::runtime_error {"Failed to set port reusable."};
#endif

        if(utility::resolve_hostname<IP_VER>(bind_addr, port, socket_type::stream, m_sockaddr) != 0)
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

        if(auto res = ::listen(m_sockfd, backlog); res != 0)
            throw std::runtime_error {"Failed to initiate listen."};
    }

    ~tcp_acceptor()
    {
        ::close(m_sockfd);
    }

    tcp_connection<IP_VER> accept() const
    {
        if constexpr(IP_VER == ip_version::v4)
        {
            sockaddr_in client;
            socklen_t len = sizeof(sockaddr_in);
            if(int sock = ::accept(m_sockfd, reinterpret_cast<sockaddr*>(&client), &len); sock >= 0)
                return tcp_connection<IP_VER> {sock, client};
            else
                throw std::runtime_error {"Failed to accept."};
        }
        else if constexpr(IP_VER == ip_version::v6)
        {
            sockaddr_in6 client;
            socklen_t len = sizeof(sockaddr_in6);
            if(int sock = ::accept(m_sockfd, reinterpret_cast<sockaddr*>(&client), &len); sock >= 0)
                return tcp_connection<IP_VER> {sock, client};
            else
                throw std::runtime_error {"Failed to accept."};
        }
        else
        {
            static_assert(IP_VER == ip_version::v4 || IP_VER == ip_version::v6);
        }
    }

    // TODO
    // std::thread async_accept(std::function<void (tcp_connection&&)> accept_handler) const
    // {
    //     return std::thread([this, callback = std::move(accept_handler)]() {
    //     });
    // }
    
    int get() const
    {
        return m_sockfd;
    }

protected:

    int m_sockfd;

    ip_version m_family;

    std::variant<sockaddr_in, sockaddr_in6> m_sockaddr {};

};

#ifdef TLS_ENABLED

template<ip_version IP_VER>
class tls_connection : public tcp_connection<IP_VER>
{
public:

    tls_connection() = delete;
    tls_connection(const tls_connection&) = delete;
    tls_connection& operator=(const tls_connection&) = delete;
    tls_connection(tls_connection&&) = default;
    tls_connection& operator=(tls_connection&&) = default;

    tls_connection(std::string_view cert_path, std::string_view key_path, std::string_view conn_addr, uint16_t port)
        : tcp_connection<IP_VER> {conn_addr, port}, m_certificate {utility::read_file(cert_path)}, m_private_key {utility::read_file(key_path)}
    {
        utility::init_ssl_system();

        // TODO Change configure function to use the cert and key string not the path
        // utility::configure_ssl_ctx(m_ctx, m_certificate, m_private_key, false);
        utility::configure_ssl_ctx(m_context, cert_path, key_path, false);
        
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
        if(m_ssl = SSL_new(m_context.get()); m_ssl == nullptr)
            throw std::runtime_error {"Failed to instatiate SSL structure."};
        SSL_set_fd(m_ssl, this->m_sockfd);

        if(auto ret = SSL_accept(m_ssl); ret != 1)
        {
            ret = SSL_get_error(m_ssl, ret);
            ERR_print_errors_fp(stderr);
            throw std::runtime_error {"Failed to accept TLS connection."};
        }
    }

    tls_connection(int socketfd, const sockaddr_in6& peer_addr, std::shared_ptr<SSL_CTX> context)
        : tcp_connection<IP_VER> {socketfd, peer_addr}, m_context {std::move(context)}
    {
        if(m_ssl = SSL_new(m_context.get()); m_ssl == nullptr)
            throw std::runtime_error {"Failed to set up SSL."};
        SSL_set_fd(m_ssl, this->m_sockfd);

        if(SSL_accept(m_ssl) != 1)
            throw std::runtime_error {"Failed to accept TLS connection."};
    }

    int read_from_socket(char* const buffer_to, size_t bytes_to_read) const override
    {
        return SSL_read(m_ssl, buffer_to, bytes_to_read);
    }

    int write_to_socket(const char* buffer_from, size_t bytes_to_write) const override
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

template<ip_version IP_VER>
class tls_acceptor : public tcp_acceptor<IP_VER>
{
public:

    tls_acceptor() = delete;
    tls_acceptor(const tls_acceptor&) = delete;
    tls_acceptor operator=(const tls_acceptor&) = delete;
    tls_acceptor(tls_acceptor&&) = default;
    tls_acceptor& operator=(tls_acceptor&&) = default;

    tls_acceptor(std::string_view cert_path, std::string_view key_path, std::string_view bind_addr, uint16_t port, size_t backlog = 5)
        : tcp_acceptor<IP_VER> {bind_addr, port, backlog}, m_certificate {utility::read_file(cert_path)}, m_private_key {utility::read_file(key_path)}
    {
        utility::init_ssl_system();
 
        // TODO Change configure function to use the cert and key string not the path
        // configure_ssl_ctx(m_ctx, m_certificate, m_private_key, true);
        utility::configure_ssl_ctx(m_context, cert_path, key_path, true);
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
            sockaddr_in client;
            socklen_t len = sizeof(sockaddr_in);
            if(int sock = ::accept(this->m_sockfd, reinterpret_cast<sockaddr*>(&client), &len); sock >= 0)
                return tls_connection<IP_VER> {sock, client, m_context};
            else
                throw std::runtime_error {"Failed to accept."};
        }
        else if constexpr(IP_VER == ip_version::v6)
        {
            sockaddr_in6 client;
            socklen_t len = sizeof(sockaddr_in6);
            if(int sock = ::accept(this->m_sockfd, reinterpret_cast<sockaddr*>(&client), &len); sock >= 0)
                return tls_connection<IP_VER> {sock, client, m_context};
            else
                throw std::runtime_error {"Failed to accept."};
        }
        else
        {
            static_assert(IP_VER == ip_version::v4 || IP_VER == ip_version::v6);
        } 
    }

private:

    std::string m_certificate;
    std::string m_private_key;

    std::shared_ptr<SSL_CTX> m_context;
    SSL* m_ssl = nullptr;

};

#endif // TLS_ENABLED

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
    udp_socket(udp_socket&&) = default;
    udp_socket& operator=(udp_socket&&) = default;

    udp_socket()
        : m_sockfd {::socket(static_cast<uint8_t>(IP_VER), static_cast<uint8_t>(socket_type::datagram), 0)}, m_family {IP_VER}, m_mode {socket_mode::non_bound}
    {}

    udp_socket(std::string_view bind_addr, uint16_t port)
        : m_sockfd {::socket(static_cast<uint8_t>(IP_VER), static_cast<uint8_t>(socket_type::datagram), 0)}, m_family {IP_VER}, m_mode {socket_mode::bound}
    {
        if(m_sockfd == -1)
            throw std::runtime_error {"Failed to create socket."};

        int reuse = 1;
        if(::setsockopt(m_sockfd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(int)) < 0)
            throw std::runtime_error {"Failed to set address reuseable."};

#ifdef SO_REUSEPORT
        if(::setsockopt(m_sockfd, SOL_SOCKET, SO_REUSEPORT, &reuse, sizeof(int)) < 0)
            throw std::runtime_error {"Failed to set port reuseable."};
#endif

        if(utility::resolve_hostname<IP_VER>(bind_addr, port, socket_type::datagram, m_sockaddr) != 0)
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
        ::close(m_sockfd);
    }

    template<typename T>
    void send(std::string_view addr_to, uint16_t port, const std::vector<T>& buffer) const
    {
        write(addr_to, port, buffer.data(), buffer.size());
    }

    template<typename T>
    void send(std::string_view addr_to, uint16_t port, const std::vector<T>& buffer, size_t size) const
    {
        write(addr_to, port, buffer.data(), size);
    }

    template<typename T, size_t SIZE>
    void send(std::string_view addr_to, uint16_t port, const std::array<T, SIZE>& buffer, size_t size = SIZE) const
    {
        write(addr_to, port, buffer.data(), size);
    }

    void send(std::string_view addr_to, uint16_t port, std::string_view buffer) const
    {
        write(addr_to, port, buffer.data(), buffer.size());
    }

    template<typename T>
    std::pair<std::vector<T>, connection_tuple> read(size_t size) const
    {
        if(m_mode != socket_mode::bound)
            throw std::runtime_error {"Socket was created without being bound to an interface."};

        std::pair<std::vector<T>, connection_tuple> ret;
        std::vector<T>& buffer = ret.first;
        buffer.resize(size);

        connection_tuple& peer = ret.second;

        if(auto bytes = read_from_socket(buffer.data(), size * sizeof(T), peer); bytes >= 0)
        {
            buffer.resize(bytes);
            return ret;
        }
        else
        {
            throw std::runtime_error {"Failed to read."};
        }
    }

    template<typename T, size_t SIZE>
    std::pair<std::array<T, SIZE>, connection_tuple> read() const
    {
        if(m_mode != socket_mode::bound)
            throw std::runtime_error {"Socket was created without being bound to an interface."};

        std::pair<std::array<T, SIZE>, connection_tuple> ret;
        std::array<T, SIZE>& buffer = ret.first;
        connection_tuple& peer = ret.second;

        if(auto bytes = read_from_socket(buffer.data(), SIZE * sizeof(T), peer); bytes >= 0)
            return ret;
        else
            throw std::runtime_error {"Failed to read."};
    }

    template<typename T>
    std::pair<size_t, connection_tuple> read(std::vector<T>& buffer_to_append, size_t size_to_append) const
    {
        if(m_mode != socket_mode::bound)
            throw std::runtime_error {"Socket was created without being bound to an interface."};

        auto old_size = buffer_to_append.size();
        if(buffer_to_append.capacity() - old_size < size_to_append)
            buffer_to_append.resize(old_size + size_to_append);

        connection_tuple peer {};

        if(auto bytes = read_from_socket(buffer_to_append.data() + old_size, size_to_append * sizeof(T), peer); bytes >= 0)
            return std::pair<size_t, connection_tuple> {bytes, peer};
        else
            throw std::runtime_error {"Failed to read."};
    }

    template<typename T, size_t SIZE>
    std::pair<size_t, connection_tuple> read(std::array<T, SIZE>& buffer_to_append, size_t size_to_append) const
    {
        static_assert(SIZE <= size_to_append);

        connection_tuple peer {};
        if(size_t bytes = read_from_socket(buffer_to_append.data(), size_to_append * sizeof(T), peer); bytes >= 0)
            return std::pair<size_t, connection_tuple> {bytes, peer};
        else
            throw std::runtime_error {"Failed to read."};
    }

    template<typename T>
    std::pair<size_t, connection_tuple> read(T* buffer_to_append, size_t size_to_append) const
    {
        connection_tuple peer {};
        if(size_t bytes = read_from_socket(reinterpret_cast<char*>(buffer_to_append), size_to_append * sizeof(T), peer); bytes >= 0)
            return std::pair<size_t, connection_tuple> {bytes, peer};
        else
            throw std::runtime_error {"Failed to read."};
    }

    int get() const
    {
        return m_sockfd;
    }

private:

    int read_from_socket(char* const buffer, size_t size, connection_tuple& peer_data) const
    {
        if constexpr(IP_VER == ip_version::v4)
        {
            socklen_t flen = sizeof(sockaddr_in);
            sockaddr_in from {};
            auto bytes = ::recvfrom(m_sockfd, buffer, size, 0, reinterpret_cast<sockaddr*>(&from), &flen);

            peer_data = utility::resolve_addrinfo<IP_VER>(reinterpret_cast<sockaddr*>(&from));

            return bytes;
        }
        else if constexpr(IP_VER == ip_version::v6)
        {
            socklen_t flen = sizeof(sockaddr_in6);
            sockaddr_in6 from {};
            return ::recvfrom(m_sockfd, buffer, size, 0, reinterpret_cast<sockaddr*>(&from), &flen);
        }
        else
        {
            static_assert(IP_VER == ip_version::v4 || IP_VER == ip_version::v6);
        }
    }

    void write(std::string_view addr_to, uint16_t port, const char* buffer, size_t length) const
    {
        std::variant<sockaddr_in, sockaddr_in6> dest;
        if(utility::resolve_hostname<IP_VER>(addr_to, port, socket_type::datagram, dest) != 0)
            throw std::runtime_error {"Failed to resolve hostname."};

        if constexpr(IP_VER == ip_version::v4)
        {
            auto& dest_ref = std::get<sockaddr_in>(dest);
            if(::sendto(m_sockfd, buffer, length, 0, reinterpret_cast<sockaddr*>(&dest_ref), sizeof(sockaddr_in)) == -1)
                throw std::runtime_error {"Failed to write."};
        }
        else if constexpr(IP_VER == ip_version::v6)
        {
            auto& dest_ref = std::get<sockaddr_in6>(dest);
            if(::sendto(m_sockfd, buffer, length, 0, reinterpret_cast<sockaddr*>(&dest_ref), sizeof(sockaddr_in6)) == -1)
                throw std::runtime_error {"Failed to write."};
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

} // namespace net

#endif // SOCKETWRAPPER_HPP

