//
// Created by timog on 23.12.18.
//

#ifndef SOCKETWRAPPER_UDPSOCKET_HPP
#define SOCKETWRAPPER_UDPSOCKET_HPP

#include "BaseSocket.hpp"

namespace socketwrapper
{

/**
 * @brief Simple udp socket class wrapping the c sockets into a c++ class
 * Only for udp sockets
 */
class UDPSocket : public BaseSocket
{

public:

    /**
     * Constructor
     * @param int family
     */
    explicit UDPSocket(int family);

    UDPSocket(UDPSocket&& other);

    UDPSocket& operator=(UDPSocket&& other);

    /**
     * @brief Reads the content sended by a client using the underlying socket and returns a buffer containing
     *  the received message
     * @param size_t max number of bytes to read
     * @param from pointer to sockaddr_in struct to store the senders data; optional - use nullptr if not wanted
     * @throws SocketReadException
     */
    template<typename T>
    std::unique_ptr<T[]> receive(size_t size, sockaddr_in* from) const;

    template<typename T>
    std::unique_ptr<T[]> receive(size_t size, sockaddr_in* from, const timeval& timeout) const;

    std::string receive_string(size_t size, sockaddr_in* from) const;

    std::string receive_string(size_t size, sockaddr_in* from, const timeval& timeout) const;

    template<typename T>
    std::vector<T> receive_vector(size_t size, sockaddr_in* from) const;

    template<typename T>
    std::vector<T> receive_vector(size_t size, sockaddr_in* from, const timeval& timeout) const;


    std::future<std::string> receive_string_async(size_t size, sockaddr_in* from) const;

    template<typename T>
    std::future<std::vector<T>> recevice_vector_async(size_t size, sockaddr_in* from) const;

    std::future<bool> receive_string_async(size_t size, sockaddr_in* from,
        const std::function<void(const std::string&, sockaddr_in*)>& callback) const;

    template<typename T>
    std::future<bool> recevice_vector_async(size_t size, sockaddr_in* from,
        const std::function<void(const std::vector<T>&, sockaddr_in*)>& callback) const;

    /**
     * Sends the data from a buffer a client using the underlying socket
     * @param buffer_from buffer with data to send
     * @param int port of the client
     * @param addr of the client
     * @throws SocketWriteException
     */
    template<typename T>
    void send_to(const T* buffer_from, size_t size, int port, in_addr_t addr) const;

    template<typename T>
    void send_to(const T* buffer_from, size_t size, int port, std::string_view addr) const;

    void send_to(const std::string& buffer, int port, std::string_view addr) const;

    void send_to(std::string_view buffer, int port, std::string_view addr) const;

    template<typename T>
    void send_to(const std::vector<T>& buffer_from, int port, std::string_view addr) const;

private:

    /**
     * @brief Read data from an underlying raw socket
     * @param buffer to read into
     * @param size of the data to read from socket
     * @param tv pointer to timeval struct to specifiy the waiting time. Directly passed to select function. If nullptr, function waites without limit
     * @throws SocketReadException
     */
    int read_raw(char* const buffer, size_t size, sockaddr_in* from, const timeval* timeout = nullptr) const;

};

template<typename T>
std::unique_ptr<T[]> UDPSocket::receive(size_t size, sockaddr_in* from) const
{
    std::unique_ptr<T[]> buffer = std::make_unique<T[]>(size);

    if(this->read_raw(reinterpret_cast<char*>(buffer.get()), size * sizeof(T), from) < 0)
        throw SocketReadException();

    return buffer;
}

template<typename T>
std::unique_ptr<T[]> UDPSocket::receive(size_t size, sockaddr_in* from, const timeval& timeout) const
{
    std::unique_ptr<T[]> buffer = std::make_unique<T[]>(size);

    if(this->read_raw(reinterpret_cast<char*>(buffer.get()), size * sizeof(T), from, &timeout) < 0)
        throw SocketReadException();

    return buffer;
}

template<typename T>
std::vector<T> UDPSocket::receive_vector(size_t size, sockaddr_in* from) const
{
    std::vector<T> buffer;
    buffer.resize(size);

    int bytes = this->read_raw(reinterpret_cast<char*>(buffer.data()), size * sizeof(T), from);
    if(bytes < 0)
        throw SocketReadException();

    buffer.resize(bytes / sizeof(T));
    return buffer;
}

template<typename T>
std::vector<T> UDPSocket::receive_vector(size_t size, sockaddr_in* from, const timeval& timeout) const
{
    std::vector<T> buffer;
    buffer.resize(size);

    int bytes = this->read_raw(reinterpret_cast<char*>(buffer.data()), size * sizeof(T), from, &timeout);
    if(bytes < 0)
        throw SocketReadException();

    buffer.resize(bytes / sizeof(T));
    return buffer;
}

template<typename T>
std::future<std::vector<T>> UDPSocket::recevice_vector_async(size_t size, sockaddr_in* from) const
{
    return std::async(std::launch::async, [this, size, from]() -> std::vector<T>
    {
        std::vector<T> buffer;
        buffer.resize(size);

        int bytes = this->read_raw(reinterpret_cast<char*>(buffer.data()), size * sizeof(T), from);
        if(bytes < 0)
            return {};

        buffer.resize(bytes / sizeof(T));
        return buffer;
    });
}

template<typename T>
std::future<bool> UDPSocket::recevice_vector_async(size_t size, sockaddr_in* from,
    const std::function<void(const std::vector<T>&, sockaddr_in*)>& callback) const
{
    return std::async(std::launch::async, [this, size, from, &callback]() -> bool
    {
        std::vector<T> buffer;
        try {
            buffer = this->receive_vector<T>(size, from);
        } catch(SocketReadException&) {
            return false;
        }

        callback(buffer, from);
        return true;
    });
}

template<typename T>
void UDPSocket::send_to(const T* buffer_from, size_t size, int port, in_addr_t addr) const
{
    if(m_socket_state != socket_state::SHUT) {
        struct sockaddr_in dest = {};
        dest.sin_family = (sa_family_t) m_family;
        dest.sin_port = htons((in_port_t) port);
        dest.sin_addr.s_addr = addr;

        std::lock_guard<std::mutex> lock(m_mutex);
        if ((::sendto(m_sockfd, (char*) buffer_from, size * sizeof(T), 0, (struct sockaddr *) &dest, sizeof(struct sockaddr_in))) == -1)
            throw SocketWriteException();
    }
}

template<typename T>
void UDPSocket::send_to(const T* buffer_from, size_t size, int port, std::string_view addr) const
{
    in_addr_t in_addr{};
    inet_pton(m_family, addr.data(), &in_addr);
    this->send_to<T>(buffer_from, size, port, in_addr);
}

template<typename T>
void UDPSocket::send_to(const std::vector<T>& buffer_from, int port, std::string_view addr) const
{
    in_addr_t in_addr{};
    inet_pton(m_family, addr.data(), &in_addr);
    this->send_to<T>(buffer_from.data(), buffer_from.size(), port, in_addr);
}

}

#endif //SOCKETWRAPPER_UDPSOCKET_HPP

