//
// Created by timog on 23.12.18.
//

#include "../include/UDPSocket.hpp"

namespace socketwrapper
{

UDPSocket::UDPSocket(int family)
    : BaseSocket(family, SOCK_DGRAM)
{}

UDPSocket::UDPSocket(UDPSocket&& other)
    : BaseSocket(std::move(other))
{}

UDPSocket& UDPSocket::operator=(UDPSocket&& other)
{
    BaseSocket::operator=(std::move(other));
    return *this;
}

void UDPSocket::send_to(const std::string& buffer, int port, std::string_view addr) const
{
    in_addr_t in_addr{};
    inet_pton(m_family, addr.data(), &in_addr);
    this->send_to<char>(buffer.data(), buffer.size(), port, in_addr);
}

void UDPSocket::send_to(std::string_view buffer, int port, std::string_view addr) const
{
    in_addr_t in_addr{};
    inet_pton(m_family, addr.data(), &in_addr);
    this->send_to<char>(buffer.data(), buffer.size(), port, in_addr);
}

std::string UDPSocket::receive_string(size_t size, sockaddr_in* from) const
{
    std::string buffer;
    buffer.resize(size + 1);

    int bytes = this->read_raw((char*) buffer.data(), size, from);
    if(bytes < 0)
        throw SocketReadException();

    if(buffer[bytes - 1] != '\0')
    {
        buffer.resize(bytes + 1);
        buffer[bytes] = '\0';
    }
    else
    {
        buffer.resize(bytes);
    }

    return buffer;
}

std::string UDPSocket::receive_string(size_t size, sockaddr_in* from, const timeval& timeout) const
{
    std::string buffer;
    buffer.resize(size + 1);

    int bytes = this->read_raw((char*) buffer.data(), size, from, &timeout);
    if(bytes < 0)
        throw SocketReadException();

    if(buffer[bytes - 1] != '\0')
    {
        buffer.resize(bytes + 1);
        buffer[bytes] = '\0';
    }
    else
    {
        buffer.resize(bytes);
    }

    return buffer;
}

std::future<std::string> UDPSocket::receive_string_async(size_t size, sockaddr_in* from) const
{
    return std::async(std::launch::async, [this, size, from]() -> std::string
    {
        std::string buffer;
        buffer.resize(size + 1);

        int bytes = this->read_raw((char*) buffer.data(), size, from);
        if(bytes < 0)
            return "";

        if(buffer[bytes - 1] != '\0')
        {
            buffer.resize(bytes + 1);
            buffer[bytes] = '\0';
        }
        else
        {
            buffer.resize(bytes);
        }

        return buffer;
    });
}

std::future<bool> UDPSocket::receive_string_async(size_t size, sockaddr_in* from, 
    const std::function<void(const std::string& buffer, sockaddr_in* from)>& callback) const
{
    return std::async(std::launch::async, [this, size, from, callback]() -> bool
    {
        std::string buffer;
        try {
            buffer = this->receive_string(size, from);
        } catch(SocketReadException&) {
            return false;
        }

        callback(buffer, from);
        return true;
    });
}

int UDPSocket::read_raw(char* const buffer, size_t size, sockaddr_in* from, const timeval* timeout) const
{
    if(m_socket_state != socket_state::SHUT)
    {
        fd_set fds;
        FD_ZERO(&fds);
        FD_SET(m_sockfd, &fds);

        int recv_fd = select(m_sockfd + 1, &fds, nullptr, nullptr, const_cast<timeval*>(timeout));
        switch(recv_fd)
        {
            case(0): // Timeout
            case(-1): // Error
                return -1;
            default:
            {
                socklen_t flen = sizeof(from);
                std::lock_guard<std::mutex> lock(m_mutex);
                int ret = ::recvfrom(m_sockfd, buffer, size, 0, (struct sockaddr*) from, &flen);
                if(ret < 0)
                    throw SocketReadException();
                return ret;
            }
        }

        
    }

    return -1;
}

}

