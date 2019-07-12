//
// Created by timog on 10.04.19.
//

#include "../include/SSLTCPSocket.hpp"

namespace socketwrapper
{

bool SSLTCPSocket::ssl_initialized = false;

SSLTCPSocket::SSLTCPSocket(int family, const char* cert, const char* key)
    : TCPSocket{family}, m_cert{cert}, m_key{key}, m_context{}, m_ssl{}
{
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

SSLTCPSocket::SSLTCPSocket(int socket_fd, sockaddr_in own_addr, bool accepted, bool bound, int family, const char* cert, const char* key)
     : TCPSocket{family, socket_fd, own_addr, bound, accepted}
{
    m_created = true;
    m_closed = false;
    m_listening = false;
    m_connected = false;

    if(m_accepted)
    {
        /* Create and configure ssl context ctx */
        m_context = SSL_CTX_new(TLS_server_method());
        SSL_CTX_set_ecdh_auto(m_context, 1);
        SSL_CTX_use_certificate_file(m_context, cert, SSL_FILETYPE_PEM);
        SSL_CTX_use_PrivateKey_file(m_context, key, SSL_FILETYPE_PEM);

        m_ssl = SSL_new(m_context);
        SSL_set_fd(m_ssl, m_sockfd);
        /* Wait for client to initiate tsl handshake */
        if(int ret = SSL_accept(m_ssl) != 1)
        {
            ret = SSL_get_error(m_ssl, ret);
            ERR_print_errors_fp(stderr);
            throw SocketAcceptingException();
        }
    }
}

SSLTCPSocket::~SSLTCPSocket()
{
    if(m_ssl)
    {
        SSL_free(m_ssl);
    }
    if(m_context)
    {
        SSL_CTX_free(m_context);
    }
    EVP_cleanup();
    ssl_initialized = false;
}

void SSLTCPSocket::connect(int port_to, in_addr_t addr_to)
{
    sockaddr_in server {};
    server.sin_family = AF_INET;
    server.sin_port = htons((in_port_t) port_to);
    server.sin_addr.s_addr = htonl(addr_to);

    if((::connect(m_sockfd, (sockaddr*) &server, sizeof(server))) != 0)
    {
        throw SocketConnectingException();
    }
    else
    {
        /* Create and configure ssl context ctx */
        m_context = SSL_CTX_new(TLS_client_method());
        SSL_CTX_set_ecdh_auto(m_context, 1);
        SSL_CTX_use_certificate_file(m_context, m_cert.c_str(), SSL_FILETYPE_PEM);
        SSL_CTX_use_PrivateKey_file(m_context, m_key.c_str(), SSL_FILETYPE_PEM);

        m_ssl = SSL_new(m_context);
        SSL_set_fd(m_ssl, m_sockfd);

        if(int ret = SSL_connect(m_ssl) != 1)
        {
            ret = SSL_get_error(m_ssl, ret);
            ERR_print_errors_fp(stderr);
            throw SocketConnectingException();
        }
        else
        {
            m_connected = true;
        }
    }
}

void SSLTCPSocket::connect(int port_to, const string &addr_to)
{
    in_addr_t inAddr;
    inet_pton(m_family, addr_to.c_str(), &inAddr);
    SSLTCPSocket::connect(port_to, inAddr);
}

std::shared_ptr<SSLTCPSocket> SSLTCPSocket::acceptShared()
{
    socklen_t len = sizeof(m_client_addr);
    int conn_fd = ::accept(m_sockfd, (sockaddr*) &m_client_addr, &len);
    if(conn_fd < 0)
    {
        throw SocketAcceptingException();
    }

    std::shared_ptr<SSLTCPSocket> connSock(new SSLTCPSocket(conn_fd, m_sockaddr_in, true, false, m_family, m_cert.c_str(), m_key.c_str()));
    return connSock;
}

std::unique_ptr<SSLTCPSocket> SSLTCPSocket::acceptUnique()
{
    socklen_t len = sizeof(m_client_addr);
    int conn_fd = ::accept(m_sockfd, (sockaddr*) &m_client_addr, &len);
    if(conn_fd < 0)
    {
        throw SocketAcceptingException();
    }

    std::unique_ptr<SSLTCPSocket> connSock(new SSLTCPSocket(conn_fd, m_sockaddr_in, true, false, m_family, m_cert.c_str(), m_key.c_str()));
    return connSock;
}

char* SSLTCPSocket::read(unsigned int size)
{
    char *buffer;
    buffer = new char[size + 1];
    if(m_connected || m_accepted) {
        /* Read the data */
        int ret = SSL_read(m_ssl, buffer, size);
        if(ret < 0)
        {
            ret = SSL_get_error(m_ssl, ret);
            if(ret == 6) {
                SSL_shutdown(m_ssl);
                m_connected = false;
                m_accepted = false;
            }
            ERR_print_errors_fp(stderr);
            throw SocketReadException();
        }
        else if(ret > 0)
        {
            buffer[size] = '\0'; //Null-terminate the String -> '' declares a char --- "" declares a String
        }
    }
    return buffer;
}

vector<char> SSLTCPSocket::readVector(unsigned int size)
{
    char* buffer = this->read(size);
    vector<char> return_buffer(buffer, buffer + size +1);
    delete[] buffer;
    return return_buffer;
}

void SSLTCPSocket::write(const char *buffer)
{
    if(m_connected || m_accepted)
    {
        /* Send the actual data */
        if(int ret = SSL_write(m_ssl, buffer, strlen(buffer)) <= 0)
        {
            ret = SSL_get_error(m_ssl, ret);
            if(ret == 6) {
                SSL_shutdown(m_ssl);
                m_connected = false;
                m_accepted = false;
            }
            ERR_print_errors_fp(stderr);
            throw SocketWriteException();
        }
    }
}

void SSLTCPSocket::write(const vector<char>& buffer)
{
    this->write(buffer.data());
}

char* SSLTCPSocket::readAll()
{
    string buffer_string;
    string tmp;
    do {
        tmp.clear();
        tmp = this->read(1);
        buffer_string += tmp;
    } while(!tmp.empty() && tmp[0] != '\n');

    char* ret = new char[buffer_string.size()+1];
    std::strcpy(ret, buffer_string.c_str());
    return ret;
}

vector<char> SSLTCPSocket::readAllVector()
{
    string buffer_string;
    string tmp;
    do {
        tmp.clear();
        tmp = this->read(1);
        buffer_string += tmp;
    } while(!tmp.empty() && tmp[0] != '\n');
    std::cout << buffer_string << std::endl;

    vector<char> ret(buffer_string.begin(), buffer_string.end());
    return ret;
}

}
