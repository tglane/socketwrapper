#ifndef SOCKETWRAPPER_NET_UTILITY_HPP
#define SOCKETWRAPPER_NET_UTILITY_HPP

#include "detail/utility.hpp"

#include <cstdint>
#include <string>

#include <netdb.h>

namespace net {

namespace detail {

inline constexpr bool is_big_endian()
{
    constexpr uint32_t big_endian = 0x03020100;
    constexpr std::array<unsigned char, 4> host_data{0, 1, 2, 3};
    constexpr uint32_t host_endian = (host_data[0] >> 24) | (host_data[1] >> 16) | (host_data[2] >> 8) | host_data[3];
    return host_endian == big_endian;
}

inline constexpr bool is_little_endian()
{
    constexpr uint32_t little_endian = 0x00010203;
    constexpr std::array<unsigned char, 4> host_data{0, 1, 2, 3};
    constexpr uint32_t host_endian = (host_data[0] >> 24) | (host_data[1] >> 16) | (host_data[2] >> 8) | host_data[3];
    return host_endian == little_endian;
}

} // namespace detail

/// Change endianess
template <typename T>
inline constexpr T to_big_endian(T in)
{
    return detail::swap_byteorder(in);
}

template <typename T>
inline constexpr T to_little_endian(T in)
{
    return detail::swap_byteorder(in);
}

template <typename T>
inline constexpr T host_to_network(T in)
{
    if constexpr (detail::is_big_endian())
        return in;
    else
        return detail::swap_byteorder<T>(in);
}

template <typename T>
inline constexpr T network_to_host(T in)
{
    if constexpr (detail::is_little_endian())
        return detail::swap_byteorder<T>(in);
    else
        return in;
}

} // namespace net

#endif
