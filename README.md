# Socketwrapper - Simple to use linux socket/networking library
[Documentation is work in progress]

Currently this is a header-only library containing classes for TCP and UDP
network connections. There are also classes for TLS encrypted TCP sockets, that
can be enabled by defining `TLS_ENABLED` before including the `socketwrapper.hpp` header (by doing you need to link against openSSL to use encryption).

There are some examples for all socket/connection types in the `examples` directory.

## Asyncronous functionality:
TODO

## Class Documentation:
All of the following classes and enum classes live in the namespace `net`.
Socket/connection classes all are not copyable but moveable and templated to distinguish between IPv4 and IPv6 by using a enum class:
```cpp
    enum class ip_version
    {
        v4,
        v6
    }
```

### span<TYPE>
Non owning abstraction of a view to memory used to generalize the interface to the reading and sending methods of the socket classes. Can be created from various container/array types.
The interface of the span class is the same as for most std container classes (providing begin(), end(), front(), back(), empty(), size(), get(), data()).
Methods:
- Constructor:
    ```cpp
    span(T* start, size_t length) noexcept;
    
    span(T* start, T* end) noexcept;
    
    span(T (&buffer)[S]) noexcept;
    
    // Create a span from a start and an end iterator.
    span(ITER start, ITER end) noexcept;
    
    // Create a span from a class that provides the same interface as the std container classes.
    span(CONTAINER&& con) noexcept;
    ```
    
### tcp_connection<IP_VER>
Represents a TCP connection that can either be constructed with the IP address and port of the remote host or by a `tcp_acceptor<IP_VER>`s accept method.
Methods:
- Constructor: .
    ```cpp
    // Construct a tcp connection that immediately connects to the remote in the constructor defined by the parameters.
    tcp_connection(const std::string_view remote_address, const uint16_t remote_port);
    ```
- Reading:
    ```cpp
    // Read as much bytes as fit into buffer and block until the read operation finishes.
    size_t read(net::span<T>&& buffer) const;
    
    // Read as much bytes as fit into buffer and block until the read operation finishes or the delay is over.
    size_t read(net::span<T>&& buffer, const std::chrono::duration<int64_t, std::milli>& delay) const;
    
    // Immediately return and call the callback function after there is data available.
    void async_read(net::span<T>&& buffer, CALLBACK_TYPE&& callback) const;
    ```
- Sending:
    ```cpp
    // Sends all data that is stored in the given buffer and blocks until all data is sent.
    size_t send(net::span<T>&& buffer) const;
    
    // Immediately returns and invokes the callback after all in the given buffer is send. Caller is responsible to keep the data the span shows alive.
    void async_send(net::span<T>&& buffer, CALLBACK_TYPE&& callback) const;
    ```
- Shorthand identifier:
    ```cpp
    using tcp_connection_v4 = tcp_connection<net::ip_version::v4>;
    using tcp_connection_v6 = tcp_connection<net::ip_version::v6>;
    ```
    
### tcp_acceptor<IP_VER>
Represents a listening TCP socket that accepts incoming connections. Returns a `tcp_connection<IP_VER>` for each accepted connection.
Methods:
- Constructor:
    ```cpp
    // Immediately creates a socket that listens on the given address and port with a connection backlog of `backlog`
    tcp_acceptor(const std::string_view bind_addr, const uint16_t port, const size_t backlog = 5);
    ```
- Accepting:
    ```cpp
    // Blocks until a connection request is available and returns a constructed and connected tcp_connection instance
    tcp_connection<IP_VER> accept() const;
    
    // Blocks until a connection request is available or the delay is over and returns a constructed and connected tcp_connection instance or std::nullopt(if no connection was established)
    std::optional<tcp_connection<IP_VER>> accept(const std::chrono::duration<int64_t, std::milli>& delay) const;
    
    // Immediately returns and invokes the callback when a new connection is established
    void async_accept(CALLBACK_TYPE&& callback) const;
    ```
- Shorthand identifier:
    ```cpp
    using tcp_acceptor_v4 = tcp_acceptor<net::ip_version::v4>;
    using tcp_acceptor_v6 = tcp_acceptor<net::ip_version::v6>;
    ```
    
### tls_connection<IP_VER> : public tcp_connection<IP_VER>
Represents a TLS encrypted TCP connection that can either be constructed with the IP address and port of the remote host or by a `tcp_acceptor<IP_VER>`s accept method.
Methods:
- Constructor:
    ```cpp
    tls_connection(std::string_view cert_path, std::string_view key_path, std::string_view conn_addr, uint16_t port);
    ```
- Reading:
    Same interface as `tcp_connection<IP_VER>`
- Writing:
    Same interface as `tcp_connection<IP_VER>`
- Shorthand identifier:
    ```cpp
    using tls_connection_v4 = tls_connection<net::ip_version::v4>;
    using tls_connection_v6 = tls_connection<net::ip_version::v6>;
    ```
    
### tls_acceptor<IP_VER> : public tcp_acceptor<IP_VER>
Represents a listening TCP socket with TLS encryption that accepts incoming connections. Returns a `tcp_connection<IP_VER>` for each accepted connection.
Methods:
- Constructor:
    ```cpp
    tls_acceptor(std::string_view cert_path, std::string_view key_path, std::string_view bind_addr, uint16_t port, size_t backlog = 5);
    ```
- Accepting:
    Same interface as `tcp_acceptor<IP_VER>`
- Shorthand identifier:
    ```cpp
    using tls_acceptor_v4 = tls_acceptor<net::ip_version::v4>;
    using tls_acceptor_v6 = tls_acceptor<net::ip_version::v6>;
    ```

### udp_socket<IP_VER>
Represents an UDP socket that can either be in "server" or "client" position.
Methods:
- Constructor:
    ```cpp
    // Creates a non-bound UDP socket that is ready to send data but can not receive data.
    udp_socket();
    
    // Creates a UDP socket that is bound to a given address and port so it can send and receive data after construction.
    udp_socket(const std::string_view bind_addr, const uint16_t port);
    ```
- Reading:
    ```cpp
    // Block until data is read into the given buffer. Reads max the amount of elements that fits into the buffer.
    std::pair<size_t, connection_info> read(span<T>&& buffer) const;
    
    // Block until data is read into the given buffer or the delay is over. Reads max the amount of elements that fits into the buffer.
    std::pair<size_t, std::optional<connection_info>> read(span<T>&& buffer, const std::chrono::duration<int64_t, std::milli>& delay) const;
    
    // Immediately return and invoke the callback when data is read into the buffer. Caller is responsible to keep the underlying buffer alive.
    void async_read(span<T>&& buffer, CALLBACK_TYPE&& callback) const;
    ```
- Writing:
    ```cpp
    // Send all data in the given buffer to a remote represented by the addr and port parameter.
    size_t send(const std::string_view addr, const uint16_t port, span<T>&& buffer) const;
    
    // Immediately return and invoke the callback after the data is sent to a remote represented by the given address and port parameter.
    void async_send(const std::string_view addr, const uint16_t port, span<T>&& buffer, CALLBACK_TYPE&& callback) const;
    ```
- Shorthand identifier:
    ```cpp
    using udp_socket_v4 = udp_socket<net::ip_version::v4>;
    using udp_socket_v6 = udp_socket<net::ip_version::v6>;
    ```

## Utility Functions:
- Run the asynchronous context:
    This function blocks until the asynchronous context runs out of registered callbacks.
    ```cpp
    void async_run();
    ```
- Change byte order:
    ```cpp
    // Change byte order from little-endian to big-endian
    template<typename T>
    constexpr inline T to_big_endian(T little);

    // Change byte order from big-endian to little-endian
    template<typename T>
    constexpr inline T to_little_endian(T big);
    ```
