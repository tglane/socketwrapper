#ifndef SOCKETWRAPPER_NET_INTERNAL_MESSAGE_NOTIFIER_EPOLL_HPP
#define SOCKETWRAPPER_NET_INTERNAL_MESSAGE_NOTIFIER_EPOLL_HPP

#include <array>
#include <map>
#include <optional>

#include <sys/epoll.h>
#include <unistd.h>

namespace net {

namespace detail {

enum class event_type : int16_t
{
    READ = EPOLLIN,
    WRITE = EPOLLOUT,
};

class event_notifier_epoll
{
    using event_t = struct ::epoll_event;

    enum class control : uint8_t
    {
        NO_OP = 0,
        EXIT_LOOP = 1,
        RELOAD_EVENT_QUEUE = 2
    };

    int m_epoll_fd;

    std::array<int, 2> m_control_pipes{};

    std::map<int, event_t> m_events{};

public:
    event_notifier_epoll()
        : m_epoll_fd{::epoll_create(1)}
    {
        if (m_epoll_fd == -1)
        {
            throw std::runtime_error{"Failed to create epoll instance when instantiating event_notifier_epoll."};
        }

        // Create pipe to stop select and add it to m_fds
        if (::pipe(m_control_pipes.data()) < 0)
            throw std::runtime_error{"Failed to create pipe when instantiating class event_notifier_epoll."};

        // Add the pipe to the epoll monitoring set
        event_t pipe_event{};
        pipe_event.events = static_cast<uint32_t>(event_type::READ);
        pipe_event.data.fd = m_control_pipes[0];
        if (::epoll_ctl(m_epoll_fd, EPOLL_CTL_ADD, m_control_pipes[0], &pipe_event) == -1)
        {
            throw std::runtime_error{"Failed to add stop event for message notifier to epoll queue."};
        }
    }

    event_notifier_epoll(const event_notifier_epoll&) = delete;

    event_notifier_epoll& operator=(const event_notifier_epoll&) = delete;

    event_notifier_epoll(event_notifier_epoll&&) = delete;

    event_notifier_epoll& operator=(const event_notifier_epoll&&) = delete;

    ~event_notifier_epoll()
    {
        // Send stop signal to epoll loop to exit background task
        const auto stop_byte = control::EXIT_LOOP;
        ::write(m_control_pipes[1], reinterpret_cast<const void*>(&stop_byte), 1);

        // Unregister all registered events
        for (const auto& event_pair : m_events)
        {
            if (event_pair.second.events & static_cast<uint32_t>(event_type::READ))
            {
                unwatch(event_pair.first, event_type::READ);
            }
            if (event_pair.second.events & static_cast<uint32_t>(event_type::WRITE))
            {
                unwatch(event_pair.first, event_type::WRITE);
            }
        }

        // Unregister control pipe read event
        event_t pipe_event{};
        pipe_event.events = static_cast<uint32_t>(event_type::READ);
        pipe_event.data.fd = m_control_pipes[0];
        ::epoll_ctl(m_epoll_fd, EPOLL_CTL_DEL, m_control_pipes[0], &pipe_event);

        ::close(m_control_pipes[0]);
        ::close(m_control_pipes[1]);
    }

    bool watch(int fd, event_type watch_for)
    {
        if (const auto it = m_events.find(fd); it != m_events.end())
        {
            // Modify the epoll event that is already registered for the socket
            auto& event_data = it->second;
            event_data.events |= static_cast<uint32_t>(watch_for);
            if (::epoll_ctl(m_epoll_fd, EPOLL_CTL_MOD, fd, &event_data) == -1)
            {
                return false;
            }
        }
        else
        {
            event_t event_data{};

            // Assign new event to epoll queue
            event_data.events = static_cast<uint32_t>(watch_for) | EPOLLET;
            event_data.data.fd = fd;
            if (::epoll_ctl(m_epoll_fd, EPOLL_CTL_ADD, fd, &event_data) == -1)
            {
                return false;
            }

            m_events.insert_or_assign(fd, event_data);
        }

        // Restart loop with updated fd set
        const auto control_byte = control::RELOAD_EVENT_QUEUE;
        ::write(m_control_pipes[1], reinterpret_cast<const void*>(&control_byte), 1);

        return true;
    }

    bool unwatch(int fd, event_type watched_for)
    {
        if (const auto& it = m_events.find(fd); it != m_events.end())
        {
            auto& event_data = it->second;

            // Remove the inparam event type from the epoll queue for this socket
            event_data.events &= ~static_cast<uint32_t>(watched_for);
            if (event_data.events == EPOLLET)
            {
                if (::epoll_ctl(m_epoll_fd, EPOLL_CTL_DEL, fd, nullptr) == -1)
                {
                    return false;
                }
                m_events.erase(it);
            }
            else
            {
                if (::epoll_ctl(m_epoll_fd, EPOLL_CTL_MOD, fd, &event_data) == -1)
                {
                    return false;
                }
            }

            // Restart loop with updated fd set
            const auto control_byte = control::RELOAD_EVENT_QUEUE;
            ::write(m_control_pipes[1], reinterpret_cast<const void*>(&control_byte), 1);

            return true;
        }
        return false;
    }

    std::optional<std::pair<int, event_type>> next_event()
    {
        auto ready_set = std::array<epoll_event, 64>{};

        while (true)
        {
            int num_ready = ::epoll_wait(m_epoll_fd, ready_set.data(), 64, -1);
            for (int i = 0; i < num_ready; ++i)
            {
                if (ready_set[i].data.fd == m_control_pipes[0])
                {
                    // Internal stop for reloading event queue after add/remove
                    auto control_byte = control::NO_OP;
                    ::read(ready_set[i].data.fd, reinterpret_cast<void*>(&control_byte), 1);
                    if (control_byte == control::EXIT_LOOP)
                    {
                        return std::nullopt;
                    }
                }
                else if (ready_set[i].events & static_cast<uint32_t>(event_type::READ))
                {
                    unwatch(ready_set[i].data.fd, event_type::READ);
                    return std::make_pair(ready_set[i].data.fd, event_type::READ);
                }
                else if (ready_set[i].events & static_cast<uint32_t>(event_type::WRITE))
                {
                    unwatch(ready_set[i].data.fd, event_type::WRITE);
                    return std::make_pair(ready_set[i].data.fd, event_type::WRITE);
                }
            }
        }
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
