#ifndef SOCKETWRAPPER_NET_INTERNAL_EXECUTOR_HPP
#define SOCKETWRAPPER_NET_INTERNAL_EXECUTOR_HPP

#include "callbacks.hpp"
#include "event_notifier.hpp"
#include "threadpool.hpp"

#include <atomic>
#include <condition_variable>
#include <functional>
#include <future>
#include <map>
#include <mutex>
#include <optional>

namespace net {

namespace detail {

inline bool operator<(const std::pair<int, event_type>& lhs, const std::pair<int, event_type>& rhs)
{
    if (lhs.first == rhs.first)
    {
        return lhs.second < rhs.second;
    }
    return lhs.first < rhs.first;
}

inline bool operator<(const std::pair<int, event_type>& lhs, const int rhs)
{
    return lhs.first < rhs;
}

inline bool operator<(const int lhs, const std::pair<int, event_type>& rhs)
{
    return lhs < rhs.first;
}

/// Class to manage all asynchronous socket io operations
class event_loop
{
    enum class context_control : uint8_t
    {
        NO_OP = 0,
        EXIT_LOOP = 1,
        RELOAD_FD_SET = 2
    };

    thread_pool m_pool;

    std::mutex m_waker_mutex{};

    event_notifier m_waker{};

    std::future<void> m_background_poll{};

    std::condition_variable m_stop_condition{};

    std::atomic_bool m_stop_token{false};

    std::multimap<std::pair<int, event_type>, std::unique_ptr<completion_handler>, std::less<>> m_completion_handlers{};

    event_loop(size_t num_threads = std::thread::hardware_concurrency())
        : m_pool{num_threads}
        , m_background_poll{std::async(std::launch::async, &event_loop::event_handling_loop, this)}
    {}

    ~event_loop()
    {
        // Remove all events from the event notifier and join its background task
        for (const auto& it : m_completion_handlers)
        {
            m_waker.unwatch(it.first.first, it.first.second);
        }
        m_stop_token.store(true);
        m_waker.cancel_next_event();
        m_background_poll.wait();
    }

    void event_handling_loop()
    {
        while (!m_stop_token.load())
        {
            const auto event = m_waker.next_event();
            if (event.has_value())
            {
                // Handle event
                auto lock = std::lock_guard<std::mutex>(m_waker_mutex);
                if (auto comp_it = m_completion_handlers.find(event.value()); comp_it != m_completion_handlers.end())
                {
                    m_pool.add_job(
                        [this, sock_fd = comp_it->first.first, completion_handler = std::move(comp_it->second)]()
                        {
                            completion_handler->invoke(sock_fd);
                            m_stop_condition.notify_one();
                        });

                    m_completion_handlers.erase(comp_it);
                }
            }
        }
    }

public:
    static event_loop& instance()
    {
        static auto handler = event_loop();
        return handler;
    }

    event_loop(const event_loop&) = delete;
    event_loop& operator=(event_loop&) = delete;
    event_loop(event_loop&&) = delete;
    event_loop& operator=(event_loop&&) = delete;

    void run()
    {
        // Wait until all registered events were handled
        auto lock = std::unique_lock<std::mutex>(m_waker_mutex);
        m_stop_condition.wait(lock,
            [this]()
            {
                // Check if there are no waiting async tasks registered or in execution
                // Its safe to check the pool for being empty because we are the only ones to insert new jobs into
                // its queue so there can not be a job inserted while this function holds the internal mutex
                return m_completion_handlers.empty() && m_pool.queue_empty() && !m_pool.busy();
            });

        // Wait until the threadpool finished executing the completion handlers
        m_pool.flush();
    }

    template <typename callback_type>
    bool add(const int sock_fd, const event_type type, callback_type&& callback)
    {
        auto lock = std::lock_guard<std::mutex>(m_waker_mutex);
        m_completion_handlers.insert(std::make_pair(
            std::make_pair(sock_fd, type), std::make_unique<callback_type>(std::forward<callback_type>(callback))));
        const auto res = m_waker.watch(sock_fd, type);
        return res;
    }

    bool remove(const int sock_fd, const event_type type)
    {
        auto result = false;
        {
            auto lock = std::lock_guard<std::mutex>(m_waker_mutex);
            if (const auto it = m_completion_handlers.find(std::make_pair(sock_fd, type));
                it != m_completion_handlers.end())
            {
                m_completion_handlers.erase(it);
                result = m_waker.unwatch(sock_fd, type);
                m_stop_condition.notify_one();
            }
        }
        return result;
    }

    void deregister(const int sock_fd)
    {
        auto lock = std::lock_guard<std::mutex>(m_waker_mutex);
        const auto fd_range = m_completion_handlers.equal_range(sock_fd);
        for (auto it = fd_range.first; it != fd_range.second;)
        {
            m_waker.unwatch(it->first.first, it->first.second);
            it = m_completion_handlers.erase(it);
        }
    }

    bool is_registered(const int sock_fd, const event_type type) const
    {
        const auto& context_it = m_completion_handlers.find(std::make_pair(sock_fd, type));
        return context_it != m_completion_handlers.end();
    }
};

} // namespace detail

/// Free function to easily wait until the event_loop runs out of registered events
inline void async_run()
{
    detail::event_loop::instance().run();
}

} // namespace net

#endif
