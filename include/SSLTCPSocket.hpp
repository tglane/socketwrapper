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

    void connect(int port_to, const string& addr_to) override;

    /**
     * @brief Waits for a client to connect returns a new socket for the connection
     *  Returned socket waits for tls/ssl-handshake initiation from client
     * @return std::unique_ptr<SSLTCPSocket>
     * @throws SocketAcceptingException
     */
    std::unique_ptr<SSLTCPSocket> accept();

    /**
     * @brief Reads "size" bytes from an existing ssl/tsl connection and returns it as char*
     * @param int size
     * @return buffer with read data
     * @throws SocketReadException
     */
    std::unique_ptr<char[]> read(unsigned int size) override;

    vector<char> read_vector(unsigned int size) override;

    /**
     * @brief Writes content of param buffer in a existing ssl/tsl connection
     * @param buffer
     * @throws SocketWriteException
     */
    void write(const char* buffer) override;

    void write(const vector<char>& buffer) override;

    /**
     * @brief Reads all currently available data to a buffer and returns it
     * @return buffer with read data
     * @throws SocketReadException
     */
    std::unique_ptr<char[]> read_all() override;

    vector<char> read_all_vector() override;

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

    SSL_CTX* m_context; /// SSL context used for the ssl connection
    SSL* m_ssl; /// SSL Object

    string m_cert;
    string m_key;

    static bool ssl_initialized; /// flag indicates whether ssl is already initialized or not
};

}

#endif //SOCKETWRAPPER_SSLTCPSOCKET_HPP
