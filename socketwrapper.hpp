#ifndef SOCKETWRAPPER_HPP
#define SOCKETWRAPPER_HPP

#include <string>
#include <string_view>
#include <array>
#include <vector>
#include <variant>
#include <stdexcept>
#include <charconv>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>

#include <iostream>
#include <cstring>

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

namespace utility {

    int resolve_hostname(std::string_view host_name,
                        uint16_t port,
                        ip_version ip_ver,
                        socket_type type,
                        std::variant<sockaddr_in, sockaddr_in6>& addr_out)
    {
        int ret;
        addrinfo* resultlist = NULL;
        addrinfo hints = {};
    
        hints.ai_family = static_cast<uint8_t>(ip_ver);
        hints.ai_socktype = static_cast<uint8_t>(type);
    
        std::array<char, 5> port_buffer;
        auto [end_ptr, ec] = std::to_chars(port_buffer.data(), port_buffer.data() + port_buffer.size(), port);
        if(ec != std::errc())
            return -1;
        std::string_view port_str {port_buffer.data(), static_cast<size_t>(end_ptr - port_buffer.data())};
    
        ret = ::getaddrinfo(host_name.data(), port_str.data(), &hints, &resultlist);
        if(ret == 0)
        {
            if(ip_ver == ip_version::v4)
                addr_out = *reinterpret_cast<sockaddr_in*>(resultlist->ai_addr);
            else if(ip_ver == ip_version::v6)
                addr_out = *reinterpret_cast<sockaddr_in6*>(resultlist->ai_addr);
            else
                ret = -1;
        }
        
        if(resultlist != NULL)
            ::freeaddrinfo(resultlist);
    
        return ret;
    }

} // namespace utility

class tcp_connection
{
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

    tcp_connection(ip_version ip_ver, std::string_view conn_addr, uint16_t port_to)
        : m_sockfd {::socket(static_cast<uint8_t>(ip_ver), static_cast<uint8_t>(socket_type::stream), 0)}, m_family {ip_ver}, m_connection {connection_status::closed}
    {
        if(m_sockfd == -1)
            throw std::runtime_error {"Failed to created socket."};

        int reuse = 1;
        if (::setsockopt(m_sockfd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse)) < 0) 
            throw std::runtime_error {"Failed to set address reusable."};
    
#ifdef SO_REUSEPORT
        if (::setsockopt(m_sockfd, SOL_SOCKET, SO_REUSEPORT, &reuse, sizeof(reuse)) < 0) 
            throw std::runtime_error {"Failed to set port reusable."};
#endif

        if(utility::resolve_hostname(conn_addr, port_to, m_family, socket_type::stream, m_peer) != 0)
            throw std::runtime_error {"Failed to resolve hostname."};

        if(std::holds_alternative<sockaddr_in>(m_peer))
        {
            auto& ref = std::get<sockaddr_in>(m_peer);
            if(auto res = ::connect(m_sockfd, reinterpret_cast<sockaddr*>(&ref), sizeof(sockaddr_in)); res != 0)
                throw std::runtime_error {"Failed to connect."};
            m_connection = connection_status::connected;
        }
        else if(std::holds_alternative<sockaddr_in6>(m_peer))
        {
            auto& ref = std::get<sockaddr_in6>(m_peer);
            if(auto res = ::connect(m_sockfd, reinterpret_cast<sockaddr*>(&ref), sizeof(sockaddr_in)); res != 0)
                throw std::runtime_error {"Failed to connect."};
            m_connection = connection_status::connected;
        }
        else
        {
            throw std::runtime_error {"Invalid family."};
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

        if(::send(m_sockfd, buffer.data(), buffer.size() * sizeof(T), 0) < 0)
            throw std::runtime_error {"Failed to send."};
    }

    void send(const std::string& buffer) const
    {
        if(m_connection == connection_status::closed)
            throw std::runtime_error {"Connection already closed."};

        if(::send(m_sockfd, buffer.c_str(), buffer.size(), 0) < 0)
            throw std::runtime_error {"Failed to send."};
    }

    template<typename T>
    std::vector<T> read(size_t size) const
    {
        if(m_connection == connection_status::closed)
            throw std::runtime_error {"Connection already closed."};

        std::vector<T> buffer;
        buffer.resize(size);

        switch(auto bytes = ::recv(m_sockfd, buffer.data(), buffer.size() * sizeof(T), 0); bytes)
        {
            case -1:
                throw std::runtime_error {"Failed to read."};
            case 0:
                m_connection = connection_status::closed;
                // Fallthrough to default case
            default:
                buffer.resize(bytes);
                return buffer;
        }
    }

    template<typename T>
    std::vector<T> send_read(const std::string& buffer, size_t size) const
    {
        send(buffer);
        return read<T>(size);
    }

    // TODO
    // template<typename T>
    // std::future<std::vector<T>> send_wait(const std::vector<T>& buffer) const
    // {}

    const int* const get() const
    {
        return &m_sockfd;
    }

private:

    tcp_connection(int socket_fd, const sockaddr_in& peer_addr)
        : m_sockfd {socket_fd}, m_family {ip_version::v4}, m_peer {peer_addr}, m_connection {connection_status::connected}
    {}

    tcp_connection(int socket_fd, const sockaddr_in6& peer_addr)
        : m_sockfd {socket_fd}, m_family {ip_version::v6}, m_peer {peer_addr}, m_connection {connection_status::connected}
    {}

    int m_sockfd;

    ip_version m_family;

    mutable connection_status m_connection;

    std::variant<sockaddr_in, sockaddr_in6> m_peer = {};

    friend class tcp_acceptor;

};

class tcp_acceptor
{
public:

    tcp_acceptor() = delete;
    tcp_acceptor(const tcp_acceptor&) = delete;
    tcp_acceptor& operator=(const tcp_acceptor&) = delete;
    tcp_acceptor(tcp_acceptor&&) = default;
    tcp_acceptor& operator=(tcp_acceptor&&) = default;

    tcp_acceptor(ip_version ip_ver, std::string_view bind_addr, uint16_t port, size_t backlog = 5)
        : m_sockfd {::socket(static_cast<uint8_t>(ip_ver), static_cast<uint8_t>(socket_type::stream), 0)}, m_family {ip_ver}
    {
        if(m_sockfd == -1)
            throw std::runtime_error {"Failed to create socket."};
     
        int reuse = 1;
        if(::setsockopt(m_sockfd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(int)) < 0) 
            throw std::runtime_error {"Failed to set address resusable."};
    
#ifdef SO_REUSEPORT
        if (::setsockopt(m_sockfd, SOL_SOCKET, SO_REUSEPORT, &reuse, sizeof(int)) < 0) 
            throw std::runtime_error {"Failed to set port reusable."};
#endif

        if(utility::resolve_hostname(bind_addr, port, m_family, socket_type::stream, m_sockaddr) != 0)
            throw std::runtime_error {"Failed to resolve hostname."};

        if(std::holds_alternative<sockaddr_in>(m_sockaddr))
        {
            auto& sockaddr_ref = std::get<sockaddr_in>(m_sockaddr);
            if(auto res = ::bind(m_sockfd, reinterpret_cast<sockaddr*>(&sockaddr_ref), sizeof(sockaddr_in)); res != 0)
                throw std::runtime_error {"Failed to bind."};
        }
        else if(std::holds_alternative<sockaddr_in6>(m_sockaddr))
        {
            auto& sockaddr_ref = std::get<sockaddr_in6>(m_sockaddr);
            if(auto res = ::bind(m_sockfd, reinterpret_cast<sockaddr*>(&sockaddr_ref), sizeof(sockaddr_in6)); res != 0)
                throw std::runtime_error {"Failed to bind."};
        }
        else
        {
            throw std::runtime_error {"Invalid family."};
        }

        if(auto res = ::listen(m_sockfd, backlog); res != 0)
            throw std::runtime_error {"Failed to initiate listen."};
    }

    ~tcp_acceptor()
    {
        ::close(m_sockfd);
    }

    tcp_connection accept() const
    {
        if(std::holds_alternative<sockaddr_in>(m_sockaddr))
        {
            sockaddr_in client;
            socklen_t len = sizeof(sockaddr_in);
            if(int sock = ::accept(m_sockfd, reinterpret_cast<sockaddr*>(&client), &len); sock >= 0)
                return tcp_connection {sock, client};
            else
                throw std::runtime_error {"Failed to accept."};
        }
        else if(std::holds_alternative<sockaddr_in6>(m_sockaddr))
        {
            sockaddr_in6 client;
            socklen_t len = sizeof(sockaddr_in6);
            if(int sock = ::accept(m_sockfd, reinterpret_cast<sockaddr*>(&client), &len); sock >= 0)
                return tcp_connection {sock, client};
            else
                throw std::runtime_error {"Failed to accept."};
        }
        else
        {
            throw std::runtime_error {"Failed to accept."};
        }
    }

    // TODO
    // std::thread async_accept(std::function<void (tcp_connection&&)> accept_handler) const
    // {
    //     return std::thread([this, callback = std::move(accept_handler)]() {
    //     });
    // }
    
    const int* const get() const
    {
        return & m_sockfd;
    }

private:

    int m_sockfd;

    ip_version m_family;

    std::variant<sockaddr_in, sockaddr_in6> m_sockaddr {};

};

class udp_socket
{

    enum class socket_mode : uint8_t
    {
        bound,
        non_bound
    };

public:

    udp_socket() = delete;
    udp_socket(const udp_socket&) = delete;
    udp_socket& operator=(const udp_socket&) = delete;
    udp_socket(udp_socket&&) = default;
    udp_socket& operator=(udp_socket&&) = default;

    udp_socket(ip_version ip_ver)
        : m_sockfd {::socket(static_cast<uint8_t>(ip_ver), static_cast<uint8_t>(socket_type::datagram), 0)}, m_family {ip_ver}, m_mode {socket_mode::non_bound}
    {}

    udp_socket(ip_version ip_ver, std::string_view bind_addr, uint16_t port)
        : m_sockfd {::socket(static_cast<uint8_t>(ip_ver), static_cast<uint8_t>(socket_type::datagram), 0)}, m_family {ip_ver}, m_mode {socket_mode::bound}
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

        if(utility::resolve_hostname(bind_addr, port, m_family, socket_type::datagram, m_sockaddr) != 0)
            throw std::runtime_error {"Failed to resolve hostname."};

        if(std::holds_alternative<sockaddr_in>(m_sockaddr))
        {
            auto& sockaddr_ref = std::get<sockaddr_in>(m_sockaddr);
            if(auto res = ::bind(m_sockfd, reinterpret_cast<sockaddr*>(&sockaddr_ref), sizeof(sockaddr_in)); res != 0)
                throw std::runtime_error {"Failed to bind."};
        }
        else if(std::holds_alternative<sockaddr_in6>(m_sockaddr))
        {
            auto& sockaddr_ref = std::get<sockaddr_in6>(m_sockaddr);
            if(auto res = ::bind(m_sockfd, reinterpret_cast<sockaddr*>(&sockaddr_ref), sizeof(sockaddr_in6)); res != 0)
                throw std::runtime_error {"Failed to bind."};
        }
        else
        {
            throw std::runtime_error {"Invalid family."};
        }
    }

    ~udp_socket()
    {
        ::close(m_sockfd);
    }

    template<typename T>
    void send(std::string_view addr_to, uint16_t port, const std::vector<T>& buffer) const
    {
        std::variant<sockaddr_in, sockaddr_in6> dest;
        if(utility::resolve_hostname(addr_to, port, m_family, socket_type::datagram, dest) != 0)
            throw std::runtime_error {"Failed to resolve hostname."};

        if(m_family == ip_version::v4)
        {
            auto& dest_ref = std::get<sockaddr_in>(dest);
            if(::sendto(m_sockfd, buffer.data(), buffer.size() * sizeof(T), 0, reinterpret_cast<sockaddr*>(&dest_ref), sizeof(sockaddr_in)) == -1)
                throw std::runtime_error {"Failed to write."};
        }
        else if(m_family == ip_version::v6)
        {
            auto& dest_ref = std::get<sockaddr_in6>(dest);
            if(::sendto(m_sockfd, buffer.data(), buffer.size() * sizeof(T), 0, reinterpret_cast<sockaddr*>(&dest_ref), sizeof(sockaddr_in6)) == -1)
                throw std::runtime_error {"Failed to write."};
        }
        else
        {
            throw std::runtime_error {"Invalid family."};
        }
    }

    template<typename T>
    std::vector<T> read(size_t size) const
    {
        if(m_mode != socket_mode::bound)
            throw std::runtime_error {"Socket was created without being bound to an interface."};

        std::vector<T> buffer;
        buffer.resize(size);

        if(m_family == ip_version::v4)
        {
            socklen_t flen = sizeof(sockaddr_in);
            sockaddr_in from {};
            if(::recvfrom(m_sockfd, buffer.data(), size * sizeof(T), 0, reinterpret_cast<sockaddr*>(&from), &flen) == -1)
                throw std::runtime_error {"Failed to read."};
            return buffer;
        }
        else if(m_family == ip_version::v6)
        {
            socklen_t flen = sizeof(sockaddr_in6);
            sockaddr_in6 from {};
            if(::recvfrom(m_sockfd, buffer.data(), size * sizeof(T), 0, reinterpret_cast<sockaddr*>(&from), &flen) == -1)
                throw std::runtime_error {"Failed to read."};
            return buffer;
        }
        else
        {
            throw std::runtime_error {"Invalid family."};
        }
    }

    const int* const get() const
    {
        return &m_sockfd;
    }

private:

    int m_sockfd;

    ip_version m_family;

    socket_mode m_mode;

    std::variant<sockaddr_in, sockaddr_in6> m_sockaddr = {};

};

} // namespace net

#endif // SOCKETWRAPPER_HPP

