//
// Created by timog on 10.04.19.
//

#include "../include/SSLTCPSocket.hpp"

namespace socketwrapper
{

bool SSLTCPSocket::ssl_initialized = false;

SSLTCPSocket::SSLTCPSocket(int family, const char* cert, const char* key)
    : TCPSocket(family), m_cert(cert), m_key(key)
{
    m_context = nullptr;
    m_ssl = nullptr;

    if(!ssl_initialized)
    {
        /* initialize SSL */
        SSL_library_init();
        SSL_load_error_strings();
        OpenSSL_add_ssl_algorithms();
        ERR_load_BIO_strings();
        ERR_load_SSL_strings();
        ssl_initialized = true;
    }

    //TODO Add error handling
}

SSLTCPSocket::SSLTCPSocket(int family, int socket_fd, sockaddr_in own_addr, int state, int tcp_state, const char* cert, const char* key)
     : TCPSocket(family, socket_fd, own_addr, state, tcp_state), m_cert(cert), m_key(key)
{
    if(m_tcp_state == tcp_state::ACCEPTED)
    {
        try
        {
            this->configure_ssl(true);
        }
        catch(SSLContextCreationException &e)
        {
            throw e;
        }

        if(int ret = SSL_accept(m_ssl) != 1)
        {
            ret = SSL_get_error(m_ssl, ret);
            ERR_print_errors_fp(stderr);
            throw SocketAcceptingException();
        }
    }
    else
    {
        this->close();
        throw SocketAcceptingException();
    }
}

SSLTCPSocket::SSLTCPSocket(SSLTCPSocket&& other)
    : TCPSocket(std::move(other))
{
    *this = std::move(other);
}

SSLTCPSocket::~SSLTCPSocket()
{
    this->close();
}

SSLTCPSocket& SSLTCPSocket::operator=(SSLTCPSocket&& other)
{
    TCPSocket::operator=(std::move(other));
    this->m_context = other.m_context;
    this->m_ssl = other.m_ssl;
    this->m_cert = other.m_cert;
    this->m_key = other.m_key;

    other.m_context = nullptr;
    other.m_ssl = nullptr;
    other.m_cert = "";
    other.m_key = "";

    return *this;
}

void SSLTCPSocket::close()
{
    if(m_socket_state != socket_state::CLOSED)
    {
        if(m_ssl)
        {
            SSL_shutdown(m_ssl);
            SSL_free(m_ssl);
        }
        if(m_context)
        {
            SSL_CTX_free(m_context);
        }
        EVP_cleanup();
        ssl_initialized = false;

        if (::close(m_sockfd) == -1) {
            throw SocketCloseException();
        } else {
            m_socket_state = socket_state::CLOSED;
            m_tcp_state = tcp_state::WAITING;
        }
    }
}

void SSLTCPSocket::connect(int port_to, in_addr_t addr_to)
{
    if(m_socket_state != socket_state::SHUT && m_tcp_state == tcp_state::WAITING)
    {

        sockaddr_in server{};
        server.sin_family = AF_INET;
        server.sin_port = htons((in_port_t) port_to);
        server.sin_addr.s_addr = htonl(addr_to);

        if ((::connect(m_sockfd, (sockaddr *) &server, sizeof(server))) != 0)
        {
            throw SocketConnectingException();
        }
        else
        {
            try
            {
                this->configure_ssl(false);
            }
            catch(SSLContextCreationException &e)
            {
                throw e;
            }

            if (int ret = SSL_connect(m_ssl) != 1)
            {
                ret = SSL_get_error(m_ssl, ret);
                ERR_print_errors_fp(stderr);
                throw SocketConnectingException();
            }
            else
            {
                m_tcp_state = tcp_state::CONNECTED;
            }
        }
    }
}

void SSLTCPSocket::connect(int port_to, std::string_view addr_to)
{
    in_addr_t inAddr{};
    inet_pton(m_family, addr_to.data(), &inAddr);

    this->connect(port_to, ntohl(inAddr));
}

std::future<bool> SSLTCPSocket::connect_async(int port, in_addr_t addr_to, const std::function<bool(SSLTCPSocket&)>& callback)
{
    return std::async(std::launch::async, [this, port, addr_to, callback]() -> bool {
        this->connect(port, addr_to);
        return callback(*this);
    });
}

std::future<bool> SSLTCPSocket::connect_async(int port, std::string_view addr_to, const std::function<bool(SSLTCPSocket&)>& callback)
{
    return std::async(std::launch::async, [this, port, addr_to, callback]() -> bool {
        in_addr_t in_addr{};
        inet_pton(this->m_family, addr_to.data(), &in_addr);

        this->connect(port, ntohl(in_addr));
        return callback(*this);
    });
}

std::unique_ptr<SSLTCPSocket> SSLTCPSocket::accept()
{
    if(m_socket_state != socket_state::CLOSED && m_tcp_state == tcp_state::LISTENING)
    {

        socklen_t len = sizeof(m_client_addr);
        int conn_fd = ::accept(m_sockfd, (sockaddr *) &m_client_addr, &len);
        if (conn_fd < 0) {
            throw SocketAcceptingException();
        }

        std::unique_ptr<SSLTCPSocket> connSock(new SSLTCPSocket(m_family, conn_fd, m_sockaddr_in, m_socket_state, tcp_state::ACCEPTED, m_cert.c_str(), m_key.c_str()));
        return connSock;
    }
    else
    {
        return std::make_unique<SSLTCPSocket>(m_family, m_cert.c_str(), m_key.c_str());
    }

}

std::future<bool> SSLTCPSocket::accept_async(const std::function<bool(SSLTCPSocket&)>& callback)
{
    return std::async(std::launch::async, [&]() -> bool {
            std::unique_ptr<SSLTCPSocket> conn = this->accept();
        return callback(*conn);
    });
}

void SSLTCPSocket::configure_ssl(bool server)
{
    /* Create and configure ssl context ctx */
    if(server)
    {
        m_context = SSL_CTX_new(TLS_server_method());
    }
    else
    {
        m_context = SSL_CTX_new(TLS_client_method());
    }
    if(!m_context)
    {
        throw SSLContextCreationException();
    }

    SSL_CTX_set_ecdh_auto(m_context, 1);
    if(SSL_CTX_use_certificate_file(m_context, m_cert.c_str(), SSL_FILETYPE_PEM) <= 0)
    {
        throw SSLContextCreationException();
    }
    if(SSL_CTX_use_PrivateKey_file(m_context, m_key.c_str(), SSL_FILETYPE_PEM) <= 0)
    {
        throw SSLContextCreationException();
    }

    m_ssl = SSL_new(m_context);
    SSL_set_fd(m_ssl, m_sockfd);
}

int SSLTCPSocket::read_raw(char* const buffer, size_t size) const
{
    if(m_socket_state != socket_state::CLOSED && (m_tcp_state == tcp_state::ACCEPTED || m_tcp_state == tcp_state::CONNECTED))
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        /* Read the data */
        int ret = SSL_read(m_ssl, buffer, size);
        if(ret < 0)
        {
            ret = SSL_get_error(m_ssl, ret);
            if(ret == 6) {
                SSL_shutdown(m_ssl);
                // TODO throw new ssl exception
                buffer[size] = '\0';
                return -1;
            }
            else
            {
                ERR_print_errors_fp(stderr);
                throw SocketReadException();
            }
        }
        else
        {
            buffer[size] = '\0'; //Null-terminate the String -> '' declares a char --- "" declares a String
            return ret;
        }
    }
    else
    {
        throw SocketReadException();
    }

    return -1;
}

void SSLTCPSocket::write_raw(const char *buffer, size_t size) const
{
    if(m_socket_state != socket_state::CLOSED && (m_tcp_state == tcp_state::ACCEPTED || m_tcp_state == tcp_state::CONNECTED))
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        /* Send the actual data */
        if(int ret = SSL_write(m_ssl, buffer, size) <= 0)
        {
            ret = SSL_get_error(m_ssl, ret);
            if(ret == 6) {
                SSL_shutdown(m_ssl);
            }
            else
            {
                ERR_print_errors_fp(stderr);
                throw SocketWriteException();
            }
        }
    }
    else
    {
        throw SocketWriteException();
    }
}

}

