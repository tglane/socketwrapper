#ifndef SOCKETWRAPPER_NET_INTERNAL_MESSAGE_NOTIFIER_KQUEUE_HPP
#define SOCKETWRAPPER_NET_INTERNAL_MESSAGE_NOTIFIER_KQUEUE_HPP

#include <array>
#include <iostream>
#include <map>
#include <optional>

#include <sys/event.h>
#include <unistd.h>

namespace net {

namespace detail {

enum class event_type : int16_t
{
    READ = EVFILT_READ,
    WRITE = EVFILT_WRITE,
};

class event_notifier_kqueue
{
    using event_t = struct ::kevent;

    enum class control : uint8_t
    {
        NO_OP = 0,
        EXIT_LOOP = 1,
        RELOAD_EVENT_QUEUE = 2
    };

    int m_kernel_queue;

    std::array<int, 2> m_control_pipes{};

    std::map<std::pair<int, event_type>, event_t> m_events{};

public:
    event_notifier_kqueue()
        : m_kernel_queue{::kqueue()}
    {
        if (m_kernel_queue == -1)
        {
            throw std::runtime_error{"Failed to create epoll instance when instantiating event_notifier_kqueue."};
        }

        // Create pipe to stop select and add it to m_fds
        if (::pipe(m_control_pipes.data()) < 0)
        {
            throw std::runtime_error{"Failed to create pipe when instantiating class event_notifier_kqueue."};
        }
        event_t pipe_event{};
        EV_SET(
            &pipe_event, m_control_pipes[0], static_cast<int16_t>(event_type::READ), EV_ADD | EV_CLEAR, 0, 0, nullptr);
        if (::kevent(m_kernel_queue, &pipe_event, 1, nullptr, 0, nullptr) == -1)
        {
            throw std::runtime_error{"Failed to add stop event for message notifier to kernel queue."};
        }
    }

    ~event_notifier_kqueue()
    {
        // Send stop signal to epoll loop to exit background task
        const auto stop_byte = control::EXIT_LOOP;
        ::write(m_control_pipes[1], reinterpret_cast<const void*>(&stop_byte), 1);

        // Unregister all registered events
        for (const auto& event_pair : m_events)
        {
            unwatch(event_pair.first.first, event_pair.first.second);
        }

        // Unregister control pipe read event
        event_t pipe_event{};
        EV_SET(&pipe_event, m_control_pipes[0], static_cast<int16_t>(event_type::READ), EV_DELETE, 0, 0, nullptr);
        ::kevent(m_kernel_queue, &pipe_event, 1, nullptr, 0, nullptr);

        ::close(m_control_pipes[0]);
        ::close(m_control_pipes[1]);
        ::close(m_kernel_queue);
    }

    event_notifier_kqueue(const event_notifier_kqueue&) = delete;

    event_notifier_kqueue& operator=(const event_notifier_kqueue&) = delete;

    event_notifier_kqueue(event_notifier_kqueue&&) = delete;

    event_notifier_kqueue& operator=(const event_notifier_kqueue&&) = delete;

    bool watch(int fd, event_type watch_for)
    {
        event_t event_data{};

        // Attach event to kernel queue
        EV_SET(&event_data, fd, static_cast<int16_t>(watch_for), EV_ADD | EV_CLEAR, 0, 0, nullptr);
        if (::kevent(m_kernel_queue, &event_data, 1, nullptr, 0, nullptr) == -1)
        {
            return false;
        }

        m_events.insert_or_assign(std::make_pair(fd, watch_for), event_data);

        // Restart loop with updated fd set
        const auto control_byte = control::RELOAD_EVENT_QUEUE;
        ::write(m_control_pipes[1], reinterpret_cast<const void*>(&control_byte), 1);

        return true;
    }

    bool unwatch(int fd, event_type watched_for)
    {
        if (const auto& event_it = m_events.find(std::tie(fd, watched_for)); event_it != m_events.end())
        {
            // Remove read event
            EV_SET(&event_it->second, fd, static_cast<int16_t>(watched_for), EV_DELETE, 0, 0, nullptr);
            if (::kevent(m_kernel_queue, &event_it->second, 1, nullptr, 0, nullptr) == -1)
            {
                return false;
            }

            m_events.erase(event_it);

            // Restart loop with updated fd set
            const auto control_byte = control::RELOAD_EVENT_QUEUE;
            ::write(m_control_pipes[1], reinterpret_cast<const void*>(&control_byte), 1);

            return true;
        }
        return false;
    }

    std::optional<std::pair<int, event_type>> next_event()
    {
        auto ready_set = std::array<event_t, 64>{};

        while (true)
        {
            const int num_ready = ::kevent(m_kernel_queue, nullptr, 0, ready_set.data(), ready_set.size(), nullptr);
            for (int i = 0; i < num_ready; i++)
            {
                if (ready_set[i].ident == static_cast<decltype(ready_set[i].ident)>(m_control_pipes[0]))
                {
                    // Internal stop for reloading event queue after add/remove
                    auto control_byte = control::NO_OP;
                    ::read(ready_set[i].ident, reinterpret_cast<void*>(&control_byte), 1);
                    if (control_byte == control::EXIT_LOOP)
                    {
                        return std::nullopt;
                    }
                }
                else if (ready_set[i].filter == static_cast<int16_t>(event_type::READ) ||
                    ready_set[i].filter == static_cast<int16_t>(event_type::WRITE))
                {
                    unwatch(ready_set[i].ident, static_cast<event_type>(ready_set[i].filter));
                    return std::make_pair(ready_set[i].ident, static_cast<event_type>(ready_set[i].filter));
                }
            }
        }

        return std::nullopt;
    }

    void cancel_next_event() const
    {
        const auto control_byte = control::EXIT_LOOP;
        ::write(m_control_pipes[1], reinterpret_cast<const void*>(&control_byte), 1);
    }
};

} // namespace detail

} // namespace net

#endif
