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
     * @throws SocketReadException
     */
    template<typename T>
    std::unique_ptr<T> receive(size_t size) const;

    template<typename T>
    std::vector<T> receive_vector(size_t size) const;

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

    template<typename T>
    void send_to(const std::vector<T>& buffer_from, int port, std::string_view addr) const;

private:

    /**
     * @brief Read data from an underlying raw socket
     * @param buffer to read into
     * @param size of the data to read from socket
     * @throws SocketReadException
     */
    int read_raw(char* const buffer, size_t size, sockaddr_in& from) const;

};

template<typename T>
std::unique_ptr<T> UDPSocket::receive(size_t size) const
{
    sockaddr_in from{};
    std::unique_ptr<T> buffer = std::make_unique<T>(size + 1);

    if(this->read_raw((char*) buffer.get(), size * sizeof(T), from) < 0)
        throw SocketReadException();

    return buffer;
}

template<typename T>
std::vector<T> UDPSocket::receive_vector(size_t size) const
{
    sockaddr_in from{};
    std::vector<T> buffer;
    buffer.resize(size + 1);

    int bytes = this->read_raw((char*) buffer.data(), size * sizeof(T), from);
    if(bytes < 0)
        throw SocketReadException();

    buffer.resize(bytes / sizeof(T));

    return buffer;
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

