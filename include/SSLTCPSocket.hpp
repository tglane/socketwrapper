//
// Created by timog on 10.04.19.
//

#ifndef SOCKETWRAPPER_SSLTCPSOCKET_HPP
#define SOCKETWRAPPER_SSLTCPSOCKET_HPP

#include <openssl/ssl.h>
#include <openssl/err.h>

#include "TCPSocket.hpp"

namespace socketwrapper {

/**
 * @briefSimple class wrapping a tcp socket and an overlying ssl/tsl connection via openssl
 *  Provides encrypted write and read operations with other ssl/tsl encrypted clients
 */
class SSLTCPSocket : public TCPSocket
{

public:

    SSLTCPSocket(int family, const char* cert, const char* key);

    SSLTCPSocket(SSLTCPSocket&& other);

    SSLTCPSocket& operator=(SSLTCPSocket&& other);

    ~SSLTCPSocket() override;

    /**
     * @brief Closes the internal socket file descriptor
     * @throws SocketCloseException
     */
    void close() override;
    
    /**
     * @brief Sets the internal socket in listening mode
     * @param int queuesize max number of clients waiting for establishing a connection
     * @throws SocketListenException
     */
    void listen(int queuesize = 5) override;

    /**
     * @brief Connects to a server and initiates the tls/ssl-handshake
     * @param int port_to
     * @param int addr_to
     * @throws SocketConnectingException SSLContextCreationException
     */
    void connect(int port_to, in_addr_t addr_to) override;

    void connect(int port_to, std::string_view addr_to) override;

    std::future<bool> connect_async(int port, in_addr_t addr_to, const std::function<bool(SSLTCPSocket&)>& callback);

    std::future<bool> connect_async(int port, std::string_view addr_to, const std::function<bool(SSLTCPSocket&)>& callback);

    /**
     * @brief Waits for a client to connect returns a new socket for the connection
     *  Returned socket waits for tls/ssl-handshake initiation from client
     * @return std::unique_ptr<SSLTCPSocket>
     * @throws SocketAcceptingException
     */
    std::unique_ptr<SSLTCPSocket> accept() const;

    std::future<bool> accept_async(const std::function<bool(SSLTCPSocket&)>& callback) const;

protected:

    /**
     * @throws SocketAcceptingException SSLContextCreationException
     */
    SSLTCPSocket(int family, int socket_fd, sockaddr_in own_addr, socket_state state, tcp_state tcp_state, std::shared_ptr<SSL_CTX> ctx);

    /**
     * @brief Configures the SSL context
     * @param bool server true if socket is in server mode, false else
     * @throws SSLContextCreationException
     */
    void configure_ssl_context(bool server);

    /**
     * @brief Read from the raw unix socket into the given buffer
     * @param buffer pointer to the buffer to read into
     * @param size size to read from the socket
     */
    int read_raw(char* const buffer, size_t size, const timeval* timeout = nullptr) const override;

    /**
     * @brief Write data to the raw unix socket from a given buffer
     * @param buffer with data to send
     * @param size of the data to send over the socket
     */
    void write_raw(const char* buffer, size_t size) const override;
    
    // SSL_CTX* m_context; /// SSL context used for the ssl connection
    std::shared_ptr<SSL_CTX> m_context;
    SSL* m_ssl = nullptr; /// SSL Object

    std::string m_cert;
    std::string m_key;

    static bool ssl_initialized; /// flag indicates whether ssl is already initialized or not
};

}

#endif //SOCKETWRAPPER_SSLTCPSOCKET_HPP
