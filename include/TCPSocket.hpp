//
// Created by timog on 23.12.18.
//

#ifndef SOCKETWRAPPER_TCPSOCKET_HPP
#define SOCKETWRAPPER_TCPSOCKET_HPP

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
    virtual void listen(int queuesize = 5);

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
     * @param size size of the buffer to read to
     * @param bytes_read Optional pointer to an size_t to store the bytes that were actually read
     * @throws SocketReadException
     */
    template<typename T>
    std::unique_ptr<T[]> read(size_t size, size_t* bytes_read = nullptr) const;
    
    std::string read_string(size_t size) const;

    template<typename T>
    std::vector<T> read_vector(size_t size) const;


    std::future<std::string> read_string_async(size_t size) const;

    template<typename T>
    std::future<std::vector<T>> read_vector_async(size_t size) const;

    std::future<bool> read_string_async(size_t size, const std::function<void(const std::string&)>& callback) const;

    template<typename T>
    std::future<bool> read_vector_async(size_t size, const std::function<void(const std::vector<T>&)>& callback) const;

    /**
     * @brief Sends the content of a buffer to connected client
     * @param buffer buffer with the content to send
     * @throws SocketWriteException
     */
    template<typename T>
    void write(const T* buffer, size_t size) const;

    void write(const std::string& buffer) const;

    void write(std::string_view buffer) const;

    template<typename T>
    void write_vector(const std::vector<T>& buffer) const;
    
    /**
     * @brief Reads all bytes available at the socket
     * @param bytes_read Optional pointer to get the number of bytes read
     * @return buffer containing all read bytes
     * @throws SocketReadException
     */
    template<typename T>
    std::unique_ptr<T[]> read_all(size_t* bytes_read = nullptr) const;

    template<typename T>
    std::vector<T> read_all_vector() const;

protected:

    TCPSocket(int family, int socket_fd, sockaddr_in own_addr, int state, int tcp_state);

    virtual int read_raw(char* const buffer, size_t size, timeval* tv = nullptr) const;

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
std::unique_ptr<T[]> TCPSocket::read(size_t size, size_t* bytes_read) const
{
    std::unique_ptr<T[]> buffer = std::make_unique<T[]>(size);

    size_t br = this->read_raw(reinterpret_cast<char*>(buffer.get()), size);
    if(br < 0)
        throw SocketReadException();

    if(bytes_read != nullptr)
        *bytes_read = br;

    return buffer;
}

template<typename T>
std::vector<T> TCPSocket::read_vector(size_t size) const 
{
    std::vector<T> buffer;
    buffer.resize(size);
    
    int bytes = this->read_raw(reinterpret_cast<char*>(buffer.data()), size * sizeof(T));
    if(bytes < 0)
        throw SocketReadException();
  
    buffer.resize(bytes / sizeof(T));
    return buffer;
}

template<typename T>
std::future<std::vector<T>> TCPSocket::read_vector_async(size_t size) const
{
    return std::async(std::launch::async, [this, size]() -> std::vector<T>
    {
        std::vector<T> buffer;
        buffer.resize(size);

        int bytes = this->read_raw(reinterpret_cast<char*>(buffer.data()), size * sizeof(T));
        if(bytes < 0)
            return {};
        
        buffer.resize(bytes / sizeof(T));
        return buffer;
    });
}

template<typename T>
std::future<bool> TCPSocket::read_vector_async(size_t size, const std::function<void(const std::vector<T>&)>& callback) const
{
    return std::async(std::launch::async, [this, size, &callback]() -> bool
    {
        std::vector<T> buffer;
        try {
            buffer = this->read_vector<T>(size);
        } catch(SocketReadException&) {
            return false;
        }

        callback(buffer);
        return false;
    });
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
std::unique_ptr<T[]> TCPSocket::read_all(size_t* bytes_read) const
{
    size_t bytes = bytes_available();
    std::unique_ptr<T[]> buffer = std::make_unique<T[]>(bytes);

    if(this->read_raw((char*) buffer.get(), bytes) < 0)
        throw SocketReadException();

    if(bytes_read != nullptr)
        *bytes_read = bytes;

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
