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
    std::unique_ptr<SSLTCPSocket> accept();

    std::future<bool> accept_async(const std::function<bool(SSLTCPSocket&)>& callback);

    /**
     * @brief Reads "size" bytes from an existing ssl/tsl connection and returns it as char*
     * @param int size
     * @return buffer with read data
     * @throws SocketReadException
     */
    std::unique_ptr<char[]> read(size_t size) const override;

    /**
     * @brief Writes content of param buffer in a existing ssl/tsl connection
     * @param buffer
     * @throws SocketWriteException
     */
    void write(const char* buffer, size_t size) const override;

    /**
     * @brief Reads all currently available data to a buffer and returns it
     * @return buffer with read data
     * @throws SocketReadException
     */
    std::unique_ptr<char[]> read_all() const override;

    std::vector<char> read_all_vector() const override;

protected:

    /**
     * @throws SocketAcceptingException SSLContextCreationException
     */
    SSLTCPSocket(int family, int socket_fd, sockaddr_in own_addr, int state, int tcp_state, const char* cert, const char* key);

    /**
     * @brief Configures the SSL context and SSL Object
     * @param bool server true if socket is in server mode, false else
     * @throws SSLContextCreationException
     */
    void configure_ssl(bool server);

    /**
     * @brief Read from the raw unix socket into the given buffer
     * @param buffer pointer to the buffer to read into
     * @param size size to read from the socket
     */
    int read_raw(char* const buffer, size_t size) const override;

    SSL_CTX* m_context; /// SSL context used for the ssl connection
    SSL* m_ssl; /// SSL Object

    std::string m_cert;
    std::string m_key;

    static bool ssl_initialized; /// flag indicates whether ssl is already initialized or not
};

}

#endif //SOCKETWRAPPER_SSLTCPSOCKET_HPP

