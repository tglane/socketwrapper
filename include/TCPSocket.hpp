//
// Created by timog on 23.12.18.
//

#ifndef SOCKETWRAPPER_TCPSOCKET_HPP
#define SOCKETWRAPPER_TCPSOCKET_HPP

#include <sys/ioctl.h>

#include "BaseSocket.hpp"

namespace socketwrapper
{

/**
 * @brief Simple tcp socket class wrapping the c socket to a c++ class
 * Only for tcp sockets
 */
class TCPSocket : public BaseSocket
{

public:

    explicit TCPSocket(int family);

    TCPSocket(TCPSocket&& other);

    TCPSocket& operator=(TCPSocket&& other);

    /**
     * @brief Closes the internal socket filedescriptor m_sockfd and resets the state
     * @throws SocketCloseException
     */
    void close() override;

    /**
     * @brief Sets the internal socket in listening mode
     * @param int queuesize max number of clients waiting for establishing a connection
     * @throws SocketListenException
     */
    void listen(int queuesize = 5);

    /**
     * @brief Establishes a connection to a server
     * @param int port_to port of the server to connect to
     * @param int addr_to ip address of the server to connect to
     * @throws SocketConnectingException
     */
    virtual void connect(int port_to, in_addr_t addr_to);

    virtual void connect(int port_to, std::string_view addr_to);

    virtual std::future<bool> connect_async(int port, in_addr_t addr_to, const std::function<bool(TCPSocket&)>& callback);

    virtual std::future<bool> connect_async(int port, std::string_view addr_to, const std::function<bool(TCPSocket&)>& callback);

    /**
     * @briefWaits for a client to connect to the socket
     *  Usable only after call of listen() and m_listeing and m_bound true
     * @return std::unique_ptr<TCPSocket> to handle the established connection
     * @throws SocketAcceptingException
     */
    std::unique_ptr<TCPSocket> accept() const;

    std::future<bool> accept_async(const std::function<bool(TCPSocket&)>& callback) const;

    /**
     * @brief Reads the content sended by a client and stores it into a buffer
     * @param buff buffer to store the given content in
     * @throws SocketReadException
     */
    template<typename T>
    std::unique_ptr<T[]> read(size_t size) const;
    
    template<typename T>
    std::vector<T> read_vector(size_t size) const;

    /**
     * @brief Sends the content of a buffer to connected client
     * @param buff buffer with the content to send
     * @throws SocketWriteException
     */
    template<typename T>
    void write(const T* buffer, size_t size) const;

    template<typename T>
    void write_vector(const std::vector<T>& buffer) const;
    
    /**
     * @brief Reads all bytes available at the socket
     * @return buffer containing all read bytes
     * @throws SocketReadException
     */
    template<typename T>
    std::unique_ptr<T[]> read_all() const;

    template<typename T>
    std::vector<T> read_all_vector() const;

    /**
     * @brief Returns the number of bytes available to read
     * @return int
     * @throws ReadBytesAvailableException
     */
    size_t bytes_available() const;

protected:

    TCPSocket(int family, int socket_fd, sockaddr_in own_addr, int state, int tcp_state);

    virtual int read_raw(char* const buffer, size_t size) const;

    virtual void write_raw(const char* buffer, size_t size) const;

    /**
     * Stores the address of a connected client
     * Only set if the socket is in "server mode" and a client is connected
     */
    sockaddr_in m_client_addr;

    int m_tcp_state;
    enum tcp_state { WAITING, CONNECTED, LISTENING, ACCEPTED };

};

template<typename T>
std::unique_ptr<T[]> TCPSocket::read(size_t size) const
{
    std::unique_ptr<T[]> buffer = std::make_unique<T[]>(size + 1);

    if(this->read_raw((char*) buffer.get(), size) < 0)
        throw SocketReadException();

    return buffer;
}

template<typename T>
std::vector<T> TCPSocket::read_vector(size_t size) const 
{
    std::vector<T> buffer;
    buffer.resize(size + 1);
    
    int bytes = this->read_raw((char*) buffer.data(), size * sizeof(T));
    if(bytes < 0)
        throw SocketReadException();
  
    buffer.resize(bytes / sizeof(T));

    return buffer;
}

template<typename T>
void TCPSocket::write(const T* buffer, size_t size) const
{
    this->write_raw((char*) buffer, size * sizeof(T));
}

template<typename T>
void TCPSocket::write_vector(const std::vector<T>& buffer) const
{
    this->write_raw((char*) buffer.data(), buffer.size() * sizeof(T));
}

template<typename T>
std::unique_ptr<T[]> TCPSocket::read_all() const
{
    size_t bytes = bytes_available();
    std::unique_ptr<T[]> buffer = std::make_unique<T[]>(bytes + 1);

    if(this->read_raw((char*) buffer.get(), bytes) < 0)
        throw SocketReadException();

    return buffer;
}

template<typename T>
std::vector<T> TCPSocket::read_all_vector() const
{
    size_t bytes = bytes_available();
    std::vector<T> buffer;
    buffer.resize(bytes / sizeof(T));

    if(this->read_raw((char*) buffer.data(), bytes) < 0)
        throw SocketReadException();

    return buffer;
}

}

#endif //SOCKETWRAPPER_TCPSOCKET_HPP
