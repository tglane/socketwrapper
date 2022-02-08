#ifndef SOCKETWRAPPER_NET_SPAN_HPP
#define SOCKETWRAPPER_NET_SPAN_HPP

#include <iterator>
#include <memory>

namespace net {

/// Generic non-owning buffer type inspired by golangs slices
/// Used as a generic buffer class to send data from and receive data to
/// Taken from my utility library at <https://github.com/tglane/t_ut>
template <typename T>
class span
{
public:
    using value_type = T;
    using reference = value_type&;
    using const_reference = const value_type&;
    using pointer = value_type*;
    using const_pointer = const value_type*;
    using iterator = pointer;
    using const_iterator = const_pointer;

    span() = delete;
    constexpr span(const span&) noexcept = default;
    constexpr span& operator=(const span&) noexcept = default;
    constexpr span(span&&) noexcept = default;
    constexpr span& operator=(span&&) noexcept = default;
    ~span() noexcept = default;

    constexpr span(pointer start, size_t length) noexcept
        : m_start{start}
        , m_size{length}
    {}

    constexpr span(pointer start, pointer end) noexcept
        : m_start{start}
        , m_size{static_cast<size_t>(std::distance(start, end) + 1)}
    {}

    template <size_t S>
    constexpr span(value_type (&buffer)[S]) noexcept
        : m_start{buffer}
        , m_size{S}
    {}

    template <typename ITER>
    constexpr span(ITER start, ITER end) noexcept
        : m_start{&(*start)}
        , m_size{static_cast<size_t>(std::distance(std::addressof(*start), std::addressof(*end)))}
    {}

    template <typename CONTAINER>
    constexpr span(CONTAINER&& con) noexcept
        : m_start{con.data()}
        , m_size{con.size()}
    {}

    constexpr pointer get()
    {
        return m_start;
    }
    constexpr const_pointer get() const
    {
        return m_start;
    }
    constexpr pointer data()
    {
        return m_start;
    }
    constexpr const_pointer data() const
    {
        return m_start;
    }

    constexpr size_t size() const
    {
        return m_size;
    }

    constexpr bool empty() const
    {
        return m_size == 0;
    }

    constexpr reference operator[](size_t index)
    {
        return m_start[index];
    }
    constexpr const_reference operator[](size_t index) const
    {
        return m_start[index];
    }

    constexpr iterator begin()
    {
        return m_start;
    }
    constexpr const_iterator begin() const
    {
        return m_start;
    }
    constexpr iterator end()
    {
        return std::addressof(m_start[m_size]);
    }
    constexpr const_iterator end() const
    {
        return std::addressof(m_start[m_size]);
    }

    constexpr reference front()
    {
        return m_start[0];
    }
    constexpr const_reference front() const
    {
        return m_start[0];
    }
    constexpr reference back()
    {
        return m_start[m_size - 1];
    }
    constexpr const_reference back() const
    {
        return m_start[m_size - 1];
    }

private:
    pointer m_start;
    size_t m_size;
};

/// Template deduction guides for class span
template <typename ITERATOR>
span(ITERATOR, ITERATOR) -> span<typename std::iterator_traits<ITERATOR>::value_type>;

template <typename CONTAINER_TYPE>
span(const CONTAINER_TYPE&)
    -> span<typename std::remove_reference<decltype(std::declval<CONTAINER_TYPE>().front())>::type>;

} // namespace net

#endif
