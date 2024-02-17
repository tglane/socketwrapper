#ifndef SOCKETWRAPPER_NET_SOCKET_OPTION_HPP
#define SOCKETWRAPPER_NET_SOCKET_OPTION_HPP

#include <algorithm>
#include <array>
#include <climits>
#include <stdexcept>
#include <string_view>
#include <type_traits>

#include <netinet/in.h>
#include <netinet/tcp.h>

namespace net {

namespace detail {

template <typename TEST_TYPE, template <auto, auto, typename> class REF_TYPE>
struct is_template_of : std::false_type
{};

template <template <auto, auto, typename> typename REF_TYPE, auto LEVEL, auto NAME, typename T>
struct is_template_of<REF_TYPE<LEVEL, NAME, T>, REF_TYPE> : std::true_type
{};

} // namespace detail

enum class option_level : int
{
    socket = SOL_SOCKET,
    ipv4 = IPPROTO_IP,
    ipv6 = IPPROTO_IPV6,
    tcp = IPPROTO_TCP
};

template <option_level, int, typename>
class option;

template <option_level LEVEL, int NAME>
class option<LEVEL, NAME, int>
{
public:
    using value_type = int;

    option() = default;

    option(int value)
        : m_value{value}
    {}

    size_t size() const
    {
        return sizeof(int);
    }

    int name() const
    {
        return NAME;
    }

    option_level level() const
    {
        return LEVEL;
    }

    int level_native() const
    {
        return static_cast<int>(LEVEL);
    }

    const int* value() const
    {
        return &m_value;
    }

    int* value()
    {
        return &m_value;
    }

private:
    int m_value;
};

template <option_level LEVEL, int NAME>
class option<LEVEL, NAME, char>
{
public:
    using value_type = char;

    option() = default;

    option(std::string_view value)
    {
        if (value.size() <= NAME_MAX)
            std::copy_n(value.begin(), value.size(), m_value.begin());
    }

    size_t size() const
    {
        return NAME_MAX;
    }

    int name() const
    {
        return NAME;
    }

    option_level level() const
    {
        return LEVEL;
    }

    int level_native() const
    {
        return static_cast<int>(LEVEL);
    }

    const char* value() const
    {
        return m_value.data();
    }

    char* value()
    {
        return m_value.data();
    }

private:
    std::array<char, NAME_MAX> m_value;
};

template <option_level LEVEL, int NAME>
class option<LEVEL, NAME, bool>
{
    using value_type = bool;

    option() = default;

    option(bool value)
        : m_value{value}
    {}

    size_t size() const
    {
        return sizeof(bool);
    }

    int name() const
    {
        return NAME;
    }

    option_level level() const
    {
        return LEVEL;
    }

    int level_native() const
    {
        return static_cast<int>(LEVEL);
    }

    const bool* value() const
    {
        return &m_value;
    }

    bool* value()
    {
        return &m_value;
    }

private:
    bool m_value;
};

template <option_level LEVEL, int NAME>
class option<LEVEL, NAME, linger>
{
public:
    using value_type = linger;

    option() = default;

    option(const linger& value)
        : m_value{value}
    {}

    size_t size() const
    {
        return sizeof(linger);
    }

    int name() const
    {
        return NAME;
    }

    option_level level() const
    {
        return LEVEL;
    }

    int level_native() const
    {
        return static_cast<int>(LEVEL);
    }

    const linger* value() const
    {
        return &m_value;
    }

    linger* value()
    {
        return &m_value;
    }

private:
    linger m_value;
};

template <option_level LEVEL, int NAME>
class option<LEVEL, NAME, sockaddr>
{
public:
    using value_type = sockaddr;

    option() = default;

    option(const sockaddr& value)
        : m_value{value}
    {}

    size_t size() const
    {
        return sizeof(sockaddr);
    }

    int name() const
    {
        return NAME;
    }

    option_level level() const
    {
        return LEVEL;
    }

    int level_native() const
    {
        return static_cast<int>(LEVEL);
    }

    const sockaddr* value() const
    {
        return &m_value;
    }

    sockaddr* value()
    {
        return &m_value;
    }

private:
    sockaddr m_value;
};

} // namespace net

#endif
