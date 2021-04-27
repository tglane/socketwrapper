/**
 * Socketwrapper Socket Library
 * Timo Glane
 * 2021
 */

#ifndef SOCKETWRAPPER_HPP
#define SOCKETWRAPPER_HPP

#include <memory>
#include <string>
#include <string_view>
#include <fstream>
#include <array>
#include <vector>
#include <unordered_map>
#include <variant>
#include <optional>
#include <chrono>
#include <future>
#include <condition_variable>
#include <mutex>
#include <functional> // TODO Remove if not needed
#include <stdexcept>
#include <charconv>
#include <utility>
#include <csignal>

#include <sys/socket.h>
#include <sys/select.h>
#include <sys/epoll.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>
#include <errno.h>

#ifdef TLS_ENABLED
// Include ssl header only when needed
#include <openssl/ssl.h>
#include <openssl/err.h>
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

/// Struct containing connection data including a string representation of peers ip address and port
struct connection_info
{
    std::string addr;
    uint16_t port;
};

/// Generic non-owning buffer type inspired by golangs slices
/// Used as a generic buffer class to send data from and receive data to
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
    explicit span(T (&buffer)[S]) noexcept
        : m_start {buffer}, m_size {S}
    {}

    template<typename ITER>
    span(ITER start, ITER end) noexcept
        : m_start {&(*start)}, m_size {static_cast<size_t>(std::distance(&(*start), &(*end)))}
    {}

    template<typename CONTAINER>
    explicit span(CONTAINER&& con) noexcept
        : m_start {con.data()}, m_size {con.size()}
    {}

    constexpr T* get() const { return m_start; }
    constexpr T* data() const { return m_start; }

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

// TODO Maybe add some sort of const_span to use in all send functions to also send string_views as CONTAINERs

namespace utility {

    class message_notifier
    {
    public:

        message_notifier(const message_notifier&) = delete;
        message_notifier& operator=(const message_notifier&) = delete;
        message_notifier(message_notifier&&) = delete;
        message_notifier& operator=(const message_notifier&&) = delete;

        static message_notifier& instance()
        {
            static message_notifier notifier;
            return notifier;
        }

        bool add(int sock_fd, std::condition_variable* cv)
        {
            if(auto [inserted, success] = m_store.emplace(sock_fd, std::pair<std::condition_variable*, epoll_event> {cv, epoll_event {}}); success)
            {
                auto& ev = inserted->second.second;

                ev.events = EPOLLIN;
                ev.data.fd = sock_fd;
                ::epoll_ctl(m_epfd, EPOLL_CTL_ADD, sock_fd, &ev);
                return true;
            }
            return false;
        }

        bool remove(int sock_fd)
        {
            if(const auto& it = m_store.find(sock_fd); it != m_store.end())
            {
                auto& ev = it->second.second;

                ::epoll_ctl(m_epfd, EPOLL_CTL_DEL, sock_fd, &ev);
                m_store.erase(it);
                return true;
            }
            return false;
        }

    private:

        message_notifier()
        {
            if(m_epfd = ::epoll_create(1); m_epfd == -1)
                throw std::runtime_error {"Failed to create epoll instance when instantiating message_notifier."};

            // Create pipe to stop select and add it to m_fds
            if(::pipe(m_pipe_fds.data()) < 0)
                throw std::runtime_error {"Failed to create pipe when instantiating class message_notifier."};

            // Add the pipe to the epoll monitoring set
            m_pipe_event.events = EPOLLIN;
            m_pipe_event.data.fd = m_pipe_fds[0];
            ::epoll_ctl(m_epfd, EPOLL_CTL_ADD, m_pipe_fds[0], &m_pipe_event);

            m_future = std::async(std::launch::async, [this]() {

                std::array<epoll_event, 64> ready_set;

                while(true)
                {
                    // TODO Other way to set max events and timeout
                    int num_ready = ::epoll_wait(this->m_epfd, ready_set.data(), 64, 1000);
                    for(int i = 0; i < num_ready; ++i)
                    {
                        if(ready_set[i].data.fd == this->m_pipe_fds[0])
                        {
                            // Stop signal via destructor
                            return;
                        }
                        else if(ready_set[i].events & EPOLLIN)
                        {
                            // Data ready to read on socket -> notify
                            if(const auto& it = this->m_store.find(ready_set[i].data.fd); it != this->m_store.end() && it->second.first != nullptr)
                                it->second.first->notify_one();
                        }
                    }
                }
            });
        }

        ~message_notifier()
        {
            // Send stop signal to epoll loop to exit background task
            char stop_byte = 0;
            ::write(m_pipe_fds[1], &stop_byte, 1);

            m_future.get();

            ::close(m_pipe_fds[0]);
            ::close(m_pipe_fds[1]);
        }

        int m_epfd;

        epoll_event m_pipe_event;
        std::array<int, 2> m_pipe_fds;

        std::future<void> m_future;

        std::unordered_map<int, std::pair<std::condition_variable*, epoll_event>> m_store;

    };

    template<ip_version IP_VER>
    inline int resolve_hostname(std::string_view host_name, uint16_t port, socket_type type, std::variant<sockaddr_in, sockaddr_in6>& addr_out)
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
    inline connection_info resolve_addrinfo(sockaddr* addr_in)
    {
        connection_info peer {};
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

    inline void init_socket_system()
    {
        static bool initialized = false;
        if(!initialized)
        {
            std::signal(SIGPIPE, SIG_IGN);

            initialized = true;
        }
    }

#ifdef TLS_ENABLED

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

    tcp_connection(const tcp_connection&) = delete;
    tcp_connection& operator=(const tcp_connection&) = delete;

    tcp_connection(tcp_connection&& rhs) noexcept
    {
        *this = std::move(rhs);
    }

    tcp_connection& operator=(tcp_connection&& rhs) noexcept
    {
        // Provide custom move assginment operator to prevent the moved socket from closing the underlying file descriptor
        if(this != &rhs)
        {
            m_sockfd = rhs.m_sockfd;
            m_family = rhs.m_family;
            m_peer = std::move(rhs.m_peer);
            m_connection = rhs.m_connection;

            rhs.m_sockfd = -1;
            rhs.m_connection = connection_status::closed;
        }
        return *this;
    }

    tcp_connection(std::string_view conn_addr, uint16_t port_to)
        : m_sockfd {::socket(static_cast<uint8_t>(IP_VER), static_cast<uint8_t>(socket_type::stream), 0)}, m_family {IP_VER}, m_connection {connection_status::closed}
    {
        utility::init_socket_system();

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
        if(m_connection != connection_status::closed && m_sockfd > 0)
            ::close(m_sockfd);
    }

    int get() const
    {
        return m_sockfd;
    }

    void wait_for_data() const
    {
        auto& notififer = utility::message_notifier::instance();

        std::condition_variable cv;
        std::mutex mut;
        std::unique_lock<std::mutex> lock {mut};
        notififer.add(m_sockfd, &cv);

        cv.wait(lock);

        notififer.remove(m_sockfd);
    }

    template<typename T>
    size_t send(span<T>&& buffer) const
    {
        if(m_connection == connection_status::closed)
            throw std::runtime_error {"Connection already closed."};

        size_t total = 0;
        while(total < buffer.size())
        {
            switch(auto bytes = write_to_socket(buffer.get() + total, buffer.size() - total); bytes)
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

    template<typename T>
    size_t read(span<T>&& buffer) const
    {
        if(m_connection == connection_status::closed)
            throw std::runtime_error {"Connection already closed."};

        switch(auto bytes = read_from_socket(reinterpret_cast<char*>(buffer.get()), buffer.size() * sizeof(T)); bytes)
        {
            case -1:
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

        timeval time_val {0, delay.count() * 1000};
        fd_set fds;
        FD_ZERO(&fds);
        FD_SET(m_sockfd, &fds);

        if(auto fd_ready = ::select(m_sockfd + 1, &fds, nullptr, nullptr, &time_val); fd_ready > 0)
        {
            switch(auto bytes = read_from_socket(reinterpret_cast<char*>(buffer.get()), buffer.size() * sizeof(T)); bytes)
            {
                case -1:
                    throw std::runtime_error {"Failed to read."};
                case 0:
                    m_connection = connection_status::closed;
                    // fall through
                default:
                    return bytes / sizeof(T);
            }
        }

        return 0;
    }

protected:

    tcp_connection() = default;

    tcp_connection(int socket_fd, const sockaddr_in& peer_addr)
        : m_sockfd {socket_fd}, m_family {ip_version::v4}, m_peer {peer_addr}, m_connection {connection_status::connected}
    {
        static_assert(IP_VER == ip_version::v4);
    }

    tcp_connection(int socket_fd, const sockaddr_in6& peer_addr)
        : m_sockfd {socket_fd}, m_family {ip_version::v6}, m_peer {peer_addr}, m_connection {connection_status::connected}
    {
        static_assert(IP_VER == ip_version::v6);
    }

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

    tcp_acceptor(tcp_acceptor&& rhs) noexcept
    {
        *this = std::move(rhs);
    }

    tcp_acceptor& operator=(tcp_acceptor&& rhs) noexcept
    {
        // Provide a custom move assginment operator to prevent the moved object from closing the underlying file descriptor
        if(this != &rhs)
        {
            m_sockfd = rhs.m_sockfd;
            m_family = rhs.m_family;
            m_sockaddr = std::move(rhs.m_sockaddr);

            rhs.m_sockfd = -1;
        }
        return *this;
    }

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
        if(m_sockfd > 0)
            ::close(m_sockfd);
    }

    int get() const
    {
        return m_sockfd;
    }

    tcp_connection<IP_VER> accept() const
    {
        if constexpr(IP_VER == ip_version::v4)
        {
            sockaddr_in client {};
            socklen_t len = sizeof(sockaddr_in);
            if(int sock = ::accept(m_sockfd, reinterpret_cast<sockaddr*>(&client), &len); sock > 0)
                return tcp_connection<IP_VER> {sock, client};
            else
                throw std::runtime_error {"Failed to accept."};
        }
        else if constexpr(IP_VER == ip_version::v6)
        {
            sockaddr_in6 client {};
            socklen_t len = sizeof(sockaddr_in6);
            if(int sock = ::accept(m_sockfd, reinterpret_cast<sockaddr*>(&client), &len); sock > 0)
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
        timeval time_val {0, delay.count() * 1000};
        fd_set fds;
        FD_ZERO(&fds);
        FD_SET(m_sockfd, &fds);

        if(auto fd_ready = ::select(m_sockfd + 1, &fds, nullptr, nullptr, &time_val); fd_ready > 0)
        {
            return std::optional<tcp_connection<IP_VER>> {accept()};
        }
        else
            return std::nullopt;
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

    tls_connection(tls_connection&& rhs) noexcept
    {
        *this = std::move(rhs);
    }

    tls_connection& operator=(tls_connection&& rhs) noexcept
    {
        // Provide custom move assginment operator to prevent moved object from deleting SSL context pointers
        if(this != &rhs)
        {
            static_cast<tcp_connection<IP_VER>&>(*this) = std::move(rhs);

            m_context = std::move(rhs.m_context);
            m_ssl = rhs.m_ssl;
            m_certificate = std::move(rhs.m_certificate);
            m_private_key = std::move(rhs.m_private_key);

            rhs.m_ssl = nullptr;
        }
        return *this;
    }

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
        static_assert(IP_VER == ip_version::v4);

        if(m_ssl = SSL_new(m_context.get()); m_ssl == nullptr)
            throw std::runtime_error {"Failed to instatiate SSL structure."};
        SSL_set_fd(m_ssl, this->m_sockfd);

        if(auto ret = SSL_accept(m_ssl); ret != 1)
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

    tls_acceptor(tls_acceptor& rhs) noexcept
    {
        *this = std::move(rhs);
    }

    tls_acceptor& operator=(tls_acceptor&& rhs) noexcept
    {
        // Provide custom move assginment operator to prevent moved object from deleting underlying SSL context
        if(this != &rhs)
        {
            static_cast<tcp_acceptor<IP_VER>&>(*this) = std::move(rhs);

            m_certificate = std::move(rhs.m_certificate);
            m_private_key = std::move(rhs.m_private_key);
            m_context = std::move(rhs.m_context);
            m_ssl = rhs.m_ssl;

            rhs.m_ssl = nullptr;
        }
        return *this;
    }

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
            sockaddr_in client {};
            socklen_t len = sizeof(sockaddr_in);
            if(int sock = ::accept(this->m_sockfd, reinterpret_cast<sockaddr*>(&client), &len); sock >= 0)
                return tls_connection<IP_VER> {sock, client, m_context};
            else
                throw std::runtime_error {"Failed to accept."};
        }
        else if constexpr(IP_VER == ip_version::v6)
        {
            sockaddr_in6 client {};
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

    std::optional<tls_connection<IP_VER>> accept(const std::chrono::duration<int64_t, std::milli>& delay) const
    {
        timeval time_val {0, delay.count() * 1000};
        fd_set fds;
        FD_ZERO(&fds);
        FD_SET(this->m_sockfd, &fds);

        if(auto fd_ready = ::select(this->m_sockfd + 1, &fds, nullptr, nullptr, &time_val); fd_ready > 0)
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

    udp_socket()
        : m_sockfd {::socket(static_cast<uint8_t>(IP_VER), static_cast<uint8_t>(socket_type::datagram), 0)}, m_family {IP_VER}, m_mode {socket_mode::non_bound}
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
        if(m_sockfd > 0)
            ::close(m_sockfd);
    }

    int get() const
    {
        return m_sockfd;
    }

    template<typename T>
    size_t send(std::string_view addr, uint16_t port, span<T>&& buffer) const
    {
        size_t total = 0;
        while(total < buffer.size())
        {
            if(auto bytes = write_to_socket(addr, port, buffer.get(), buffer.size()); bytes >= 0)
                total += bytes;
            else
                throw std::runtime_error {"Failed to send."};
        }

        return total / sizeof(T);
    }

    template<typename T>
    std::pair<size_t, connection_info> read(span<T>&& buffer) const
    {
        std::pair<size_t, connection_info> pair {};
        if(auto bytes = read_from_socket(reinterpret_cast<char*>(buffer.get()), buffer.size() * sizeof(T), &(pair.second)); bytes >= 0)
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
        timeval time_val {0, delay.count() * 1000};
        fd_set fds;
        FD_ZERO(&fds);
        FD_SET(m_sockfd, &fds);

        if(auto fd_ready = ::select(m_sockfd + 1, &fds, nullptr, nullptr, &time_val); fd_ready > 0)
        {
            std::pair<size_t, connection_info> pair {};
            if(auto bytes = read_from_socket(reinterpret_cast<char*>(buffer.get()), buffer.size() * sizeof(T), &(pair.second)); bytes >= 0)
            {
                pair.first = bytes / sizeof(T);
                return pair;
            }
            else
            {
                throw std::runtime_error {"Failed to read."};
            }
        }

        return {0, std::nullopt};
    }

private:

    int read_from_socket(char* const buffer, size_t size, connection_info* peer_data = nullptr) const
    {
        if constexpr(IP_VER == ip_version::v4)
        {
            socklen_t flen = sizeof(sockaddr_in);
            sockaddr_in from {};
            auto bytes = ::recvfrom(m_sockfd, buffer, size, 0, reinterpret_cast<sockaddr*>(&from), &flen);

            if(peer_data)
                *peer_data = utility::resolve_addrinfo<IP_VER>(reinterpret_cast<sockaddr*>(&from));

            return bytes;
        }
        else if constexpr(IP_VER == ip_version::v6)
        {
            socklen_t flen = sizeof(sockaddr_in6);
            sockaddr_in6 from {};
            auto bytes = ::recvfrom(m_sockfd, buffer, size, 0, reinterpret_cast<sockaddr*>(&from), &flen);

            if(peer_data)
                *peer_data = utility::resolve_addrinfo<IP_VER>(reinterpret_cast<sockaddr*>(&from));

            return bytes;
        }
        else
        {
            static_assert(IP_VER == ip_version::v4 || IP_VER == ip_version::v6);
        }
    }

    int write_to_socket(std::string_view addr_to, uint16_t port, const char* buffer, size_t length) const
    {
        std::variant<sockaddr_in, sockaddr_in6> dest;
        if(utility::resolve_hostname<IP_VER>(addr_to, port, socket_type::datagram, dest) != 0)
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

} // namespace net

#endif // SOCKETWRAPPER_HPP
