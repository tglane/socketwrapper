# Socketwrapper - Simple to use linux socket/networking library
[Documentation is work in progress]

Currently this is a header-only library containing classes for TCP and UDP
network connections. There are also classes for TLS encrypted TCP sockets, which requires to link 
against OpenSSL (use the compile flags `-lssl -lcrypto`) and some other utility
functions.

The only requirements are a C++17 compliant compiler (make sure to compile with
this version!), and `pthreads` (you need to link with `lpthread`) and OpenSSL
(but only if you use the `tls.hpp` header).

There are some examples for all socket/connection types in the `examples` directory.

## Asyncronous functionality:
*TODO Describe the design of the asynchronous system*

## Class Documentation:
All of the following classes and enum classes live in the namespace `net`.
Socket/connection classes all are not copyable but moveable and templated to distinguish between IPv4 and IPv6 by using a enum class:
```cpp
    enum class ip_version
    {
        v4,
        v6
    };
```

```cpp
    enum class socket_type : uint8_t
    {
        unspecified = AF_UNSPEC,
        stream = SOCK_STREAM,
        datagram = SOCK_DGRAM
    };
```

```cpp
    enum class option_level : int
    {
        socket = SOL_SOCKET,
        ipv4 = IPPROTO_IP
        ipv6 = IPPROTO_IPV6
        tcp = IPPROTO_TCP
    };
```

### span<typename TYPE>
>#include "socketwrapper/span.hpp" (also included by all socket headers)

Non owning abstraction of a view to memory used to generalize the interface to the reading and sending methods of the socket classes.
Can be created from all container types that can be represented by a pointer and a length.
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
    
### endpoint<ip_version IP_VER>
>#include "socketwrapper/endpoint.hpp"

Represents a endpoint of a IP/socket connection.
Methods:
- Constructor:
    ```cpp
    // Constructs an endpoint from a string representation of a IP address, a port and the type of the connection (stream or datagram)
    endpoint(std::string_view address_string, uint16_t port, socket_type connection_type);
    
    // Constructs an endpoint<ip_version::v4> from a POSIX struct sockaddr_in
    endpoint(const sockaddr_in& address);
    
    // Constructs an endpoint<ip_version::v6> from a POSIX struct sockaddr_in6
    endpoint(const sockaddr_in6& address);
    ```
- Accessor:
    ```cpp
    // Returns the IP address of the represented endpoint in string representation
    const std::string& get_addr_string() const;
    
    // Returns the port of the represented endpoint as a uint16_t
    uint16_t get_port() const;
    
    // Returns information of the endpoint represented by a const reference to a POSIX struct sockaddr
    const sockaddr& get_addr() const;
    
    // Returns information of the endpoint represented by a reference to a POSIX struct sockaddr
    sockaddr& get_addr();
    ```

### option<option_level LEVEL, int NAME, typename T>
This class is used in the methods ```base_socket::get_option```, ```base_socket::get_option_value``` and ```base_socket::set_option``` to set and get socket options.
It is included implicitly with the class ```base_socket```.

Methods:
- Constructors:
    ```cpp
    option() = default;
    
    option(int value);
    ```
- Accessors/Modifiers:
    ```cpp
    size_t size() const;
    
    int name() const;
    
    option_level level() const;
    
    int level_native() const;
    
    const int* value() const;
    
    int* value();
    ```

Valid template specializations for parameter T are:
* int
* bool
* linger
* sockaddr

### base_socket
This class is implicitly included with every socket class that inherits from the class ```base_socket```.

Represents the basic functionalities of the native socket handle. The other high-level socket abstractions are all dervived from this class.
Methods:
- Set/get socket options:
    ```cpp
    // Set a socket option where the option is represented by a valid template specialization of net::option<net::option_level LEVEL, int NAME, typename T>
    template <typename OPTION_TYPE,
        typename = std::enable_if_t<detail::is_template_of<OPTION_TYPE, option>::value, bool>>
    void set_option(OPTION_TYPE&& opt_val);
    
    // Get a current socket option where the option type needs to be a valid template specialization of net::option<net::option_level LEVEL, int NAME, typename T>
    template <typename OPTION_TYPE,
        typename = std::enable_if_t<detail::is_template_of<OPTION_TYPE, option>::value, bool>>
    OPTION_TYPE get_option() const
    
    // Get the current value of a socket option where the option type needs to be a valid template specialization of net::option<net::option_level LEVEL, int NAME, typename T>
    template <typename OPTION_TYPE,
        typename = std::enable_if_t<detail::is_template_of<OPTION_TYPE, option>::value, bool>>
    typename OPTION_TYPE::value_type get_option_value() const
    ```
- Other:
    ```cpp
    // Get the underlying socket handle
    int get() const;
    
    // Get the ip version of the represented socket
    ip_version family() const;
    ```

### tcp_connection<ip_version IP_VER> : public base_socket
>#include "socketwrapper/tcp.hpp"

Represents a TCP connection that can either be constructed with the IP address and port of the remote host or by a `tcp_acceptor<IP_VER>`s accept method.
Methods:
- Constructor:
    ```cpp
    // Default constructor of a not connected tcp connection
    tcp_connection();
    
    // Construct a tcp connection from a net::endpoint<IP_VER>
    tcp_connection(const endpoint<IP_VER>& endpoint);
    ```
- Config:
    ```cpp
    // Connect a default constructed socket to a given endpoint
    void connect(const endpoint<IP_VER>& endpoint);
    ```
- Reading:
    ```cpp
    // Read as much bytes as fit into buffer and block until the read operation finishes.
    size_t read(net::span<T>buffer) const;
    
    // Read as much bytes as fit into buffer and block until the read operation finishes or the delay is over.
    size_t read(net::span<T> buffer, const std::chrono::duration<int64_t, std::milli>& delay) const;
    
    // Immediately return and call the callback function after there is data available.
    void async_read(net::span<T> buffer, CALLBACK_TYPE&& callback) const;

    // Immediately returns an awaitable that can be co_awaited in a C++20 coroutine
    // Only available when compiling with C++20 or higher
    net::op_awaitable<size_t, net::tcp_connection::stream_read_operation<T>> async_read(net::span<T> buffer) const;

    // Immediately return and get a future to get the number of elements received at a later timepoint
    std::future<size_t> promised_read(net::span<T> buffer) const;
    ```
- Sending:
    ```cpp
    // Sends all data that is stored in the given buffer and blocks until all data is sent.
    size_t send(net::span<T> buffer) const;
    
    // Immediately returns and invokes the callback after all in the given buffer is send. Caller is responsible to keep the data the span shows alive.
    void async_send(net::span<T> buffer, CALLBACK_TYPE&& callback) const;

    // Immediately returns an awaitable that can be co_awaited in a C++20 coroutine
    // Only available when compiling with C++20 or higher
    net::op_awaitable<size_t, net::tcp_connection::stream_write_operation<T>> async_send(net::span<T> buffer) const;

    // Immediately return and get a future to get the number of elements written at a later point in time
    std::future<size_t> promised_send(net::span<T> buffer) const;
    ```
- Shorthand identifier:
    ```cpp
    using tcp_connection_v4 = tcp_connection<net::ip_version::v4>;
    using tcp_connection_v6 = tcp_connection<net::ip_version::v6>;
    ```
    
### tcp_acceptor<ip_version IP_VER> public base_socket
>#include "socketwrapper/tcp.hpp"

Represents a listening TCP socket that accepts incoming connections. Returns a `tcp_connection<IP_VER>` for each accepted connection.
Methods:
- Constructor:
    ```cpp
    // Default constructor of a non-bound tcp acceptor
    tcp_acceptor();
    
    // Immediately creates a socket that listens on the given address and port with a connection backlog of `backlog`
    tcp_acceptor(const endpoint<IP_VER>& endpoint, const size_t backlog = 5);
    ```
- Config:
    ```cpp
    // Bind a non-bound acceptor to a internal endpoint and set the socket in listening state
    void activate(const endpoint<IP_VER>& endpoint, const size_t backlog = 5);
    ```
- Accepting:
    ```cpp
    // Blocks until a connection request is available and returns a constructed and connected tcp_connection instance
    tcp_connection<IP_VER> accept() const;
    
    // Blocks until a connection request is available or the delay is over and returns a constructed and connected tcp_connection instance or std::nullopt(if no connection was established)
    std::optional<tcp_connection<IP_VER>> accept(const std::chrono::duration<int64_t, std::milli>& delay) const;
    
    // Immediately returns and invokes the callback when a new connection is established
    void async_accept(CALLBACK_TYPE&& callback) const;

    // Immediately returns an awaitable that can be co_awaited in a C++20 coroutine
    // Only available when compiling with C++20 or higher
    net::op_awaitable<net::tcp_connection<IP_VER>, net::tcp_acceptor::stream_accept_operation> async_accept() const;

    // Immediately return and get a future to access the accepted socket at a later point in time
    std::future<net::tcp_connection<IP_VER>> promised_accept() const;
    ```
- Shorthand identifier:
    ```cpp
    using tcp_acceptor_v4 = tcp_acceptor<net::ip_version::v4>;
    using tcp_acceptor_v6 = tcp_acceptor<net::ip_version::v6>;
    ```
    
### tls_connection<ip_version IP_VER> : public tcp_connection<IP_VER>
>#include "socketwrapper/tls.hpp"

Represents a TLS encrypted TCP connection that can either be constructed with the IP address and port of the remote host or by a `tcp_acceptor<IP_VER>`s accept method.
Methods:
- Constructor:
    ```cpp
    // Construct a non connected tls connection
    tls_connection(std::string_view cert_path, std::string_view key_path);
    
    // Construct a tls connection from an endpoint and immediately connect it
    tls_connection(std::string_view cert_path, std::string_view key_path, const endpoint<IP_VER>& endpoint);
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
    
### tls_acceptor<ip_version IP_VER> : public tcp_acceptor<IP_VER>
>#include "socketwrapper/tls.hpp"
Represents a listening TCP socket with TLS encryption that accepts incoming connections. Returns a `tcp_connection<IP_VER>` for each accepted connection.
Methods:
- Constructor:
    ```cpp
    // Construct a non-bound tls_acceptor
    tls_acceptor(std::string_view cert_path, std::string_view key_path);
    
    // Construct a tls acceptor from an endpoint and set it into listening state
    tls_acceptor(std::string_view cert_path, std::string_view key_path, const endpoint<IP_VER>& endpoint);
    ```
- Accepting:
    Same interface as `tcp_acceptor<IP_VER>`
- Shorthand identifier:
    ```cpp
    using tls_acceptor_v4 = tls_acceptor<net::ip_version::v4>;
    using tls_acceptor_v6 = tls_acceptor<net::ip_version::v6>;
    ```

### udp_socket<ip_version IP_VER> : public base_socket
>#include "socketwrapper/udp.hpp"

Represents an UDP socket that can either be in "server" or "client" position.
Methods:
- Constructor:
    ```cpp
    // Creates a non-bound UDP socket that is ready to send data but can not receive data.
    udp_socket();
    
    // Creates a UDP socket that is bound to a given endpoint so it can send and receive data directly after construction
    udp_socket(const endpoint<IP_VER>& endpoint);
    ```
- Config:
    ```cpp
    // Bind a non-bound udp socket to a given endpoint so that it is able to receive data afterwards
    void bind(const endpoint<IP_VER>& endpoint);
    ```
- Reading:
    ```cpp
    // Block until data is read into the given buffer. Reads max the amount of elements that fits into the buffer.
    std::pair<size_t, endpoint<IP_VER>> read(span<T> buffer) const;
    
    // Block until data is read into the given buffer or the delay is over. Reads max the amount of elements that fits into the buffer.
    std::pair<size_t, std::optional<endpoint<IP_VER>>> read(span<T> buffer, const std::chrono::duration<int64_t, std::milli>& delay) const;
    
    // Immediately return and invoke the callback when data is read into the buffer. Caller is responsible to keep the underlying buffer alive.
    void async_read(span<T> buffer, CALLBACK_TYPE&& callback) const;

    // Immediately returns an awaitable that can be co_awaited in a C++20 coroutine
    // Only available when compiling with C++20 or higher
    net::op_awaitable<std::pair<size_t, std::optional<endpoint<IP_VER>>>, net::udp_socket::dgram_read_operation<T>> async_read(span<T> buffer) const;

    // Immediately return and get a future to get the number of elements read and the connection info of the sender at a later point in time
    std::future<std::pair<size_t, endpoint<IP_VER>>> promised_read(span<T> buffer) const;
    ```
- Writing:
    ```cpp
    // Send all data in the given buffer to a remote endpoint.
    size_t send(const endpoint<IP_VER>& endpoint_to, span<T> buffer) const;
    
    // Immediately return and invoke the callback after the data is sent to a remote represented by the given address and port parameter.
    void async_send(const endpoint<IP_VER>& endpoint_to, span<T> buffer, CALLBACK_TYPE&& callback) const;
    
    // Immediately returns an awaitable that can be co_awaited in a C++20 coroutine
    // Only available when compiling with C++20 or higher
    net::op_awaitable<size_t, net::udp_socket::dgram_write_operation<T>> async_write(const endpoint<IP_VER>& endpoint_to, span<T> buffer) const;

    // Immediately return and get a future to get the number of elements written at a later point in time
    std::future<size_t> promised_send(const endpoint<IP_VER>& endpoint_to, span<T> buffer) const;
    ```
- Shorthand identifier:
    ```cpp
    using udp_socket_v4 = udp_socket<net::ip_version::v4>;
    using udp_socket_v6 = udp_socket<net::ip_version::v6>;
    ```

### task<return_type>
>#include "socketwrapper/task.hpp"

Representation of a lazily evaluated coroutine without any special functionality that holds a `std::coroutine_handle` of the parent coroutine frame.
It defines a `promise_type` and implements the `awaitable` which allows awaiting this type.
To start execution, this type needs to be awaited by a parent coroutine.
User can use `net::block_on()` or `net::to_future()` to transform a coroutine that returns a `net::task` into a synchronous function.
This is a helper class to give a user a coroutine class to utilize the networking functions that return an `net::op_awaitable`.
This class is only available when compiling with C++20 or higher

Example of a coroutine that returns `net::task`:
```cpp
net::task<size_t> example(size_t input)
{
    co_return input * 2;
}

net::task<void> example_two()
{
    auto number = co_await example(5);
}
```

## Utility Functions:
>#include "socketwrapper/utility.hpp"

All of the following functions live in the namespace `net`

- Change byte order:
    ```cpp
    // Change byte order from little-endian to big-endian
    template <typename T>
    inline constexpr T to_big_endian(T little);

    // Change byte order from big-endian to little-endian
    template <typename T>
    inline constexpr T to_little_endian(T big);

    // Change byteorder from host byte order to network byte order if they differ
    template <typename T>
    inline constexpr T host_to_network(T in);

    // Change byteorder from network byte order to host byte order if they differ
    template <typename T>
    inline constexpr T network_to_host(T in);
    ```

## Runtime helper functions:
This functions are implicitly included with every socket header file.

- Run the asynchronous context until all callbacks are handled:
    ```cpp
    // Blocks until all registered async operations are handled and all completion handlers finished execution.
    void async_run();
    ```
- Block the current thread until the coroutine represented by the `net::task` parameter is completely evaluated.
Only available when compiling with C++20 or higher
    ```cpp
    template <typename return_type>
    return_type block_on(net::task<return_type> awaitable_task);
    ```
- Convert a lazily evaluated coroutine that is represented by `net::task` into an eagerly evaluated future.
By performing this conversion the task starts execution right away until it reaches its first suspension point while
the task itself would normally be suspended right away and only starts execution if it is awaited.
Only available when compiling with C++20 or higher
    ```cpp
    template <typename return_type>
    std::future<return_type> spawn(net::task<return_type> awaitable_task);
    ```
