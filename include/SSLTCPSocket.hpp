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
 * Simple class wrapping a tcp socket and an overlying ssl/tsl connection via openssl
 * Provides encrypted write and read operations with other ssl/tsl encrypted clients
 */
class SSLTCPSocket : public TCPSocket {

public:

    using Ptr = std::shared_ptr<SSLTCPSocket>;

    SSLTCPSocket(int family, const char* cert, const char* key);

    ~SSLTCPSocket() override;

    /**
     * @brief Connects to a server and initiates the tls/ssl-handshake
     * @param port_to
     * @param addr_to
     */
    void connect(int port_to, in_addr_t addr_to) override;
    void connect(int port_to, const string& addr_to) override;

    /**
     * @brief Waits for a client to connect returns a new socket for the connection
     * Returned socket waits for tls/ssl-handshake initiation from client
     */
    std::shared_ptr<SSLTCPSocket> acceptShared();

    std::unique_ptr<SSLTCPSocket> acceptUnique();

    /**
     * @brief Reads "size" bytes from an existing ssl/tsl connection and returns it as char*
     * @param size
     * @return
     */
    char* read(unsigned int size) override;

    vector<char> readVector(unsigned int size);

    /**
     * @brief Writes content of param buffer in a existing ssl/tsl connection
     * @param buffer
     */
    void write(const char* buffer) override;

    void write(const vector<char> buffer) override;

    char* readAll() override;

    vector<char> readAllVector() override;

protected:

    SSLTCPSocket(int socket_fd, sockaddr_in own_addr, bool accepted, bool bound, int family, const char* cert, const char* key);

    SSL_CTX* m_context; /// SSL context used for the ssl connection
    SSL* m_ssl; /// SSL Object

    string m_cert;
    string m_key;

    static bool ssl_initialized; /// flag indicates whether ssl is already initialized or not

};

}

#endif //SOCKETWRAPPER_SSLTCPSOCKET_HPP
