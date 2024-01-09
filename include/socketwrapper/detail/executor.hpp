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
#include <thread>

namespace net {

namespace detail {

inline bool operator<(const std::pair<int, event_type>& lhs, const std::pair<int, event_type>& rhs)
{
    if(lhs.first == rhs.first)
        return lhs.second < rhs.second;
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
class executor
{
private:
    enum class context_control : uint8_t
    {
        NO_OP = 0,
        EXIT_LOOP = 1,
        RELOAD_FD_SET = 2
    };

    /// No op callback used to add the pipe file descriptor to manage the executor
    /// This never gets called
    struct no_op_callback : public async_callback
    {
        no_op_callback()
            : async_callback{}
        {}

        void invoke() const override
        {
            // no op callback does nothing when invoked
        }
    };

    thread_pool m_pool;

    std::mutex m_waker_mutex{};

    event_notifier m_waker{};

    std::future<void> m_background_poll{};

    std::condition_variable m_stop_condition{};

    std::atomic_bool m_stop_token{false};

    std::multimap<std::pair<int, event_type>, std::unique_ptr<async_callback>, std::less<>> m_completion_handlers{};

    executor(size_t num_threads = std::thread::hardware_concurrency())
        : m_pool{num_threads}
        , m_background_poll{std::async(std::launch::async, &executor::event_handling_loop, this)}
    {}

    ~executor()
    {
        // Remove all events from the event notifier and join its background task
        for(const auto& it : m_completion_handlers)
        {
            m_waker.unwatch(it.first.first, it.first.second);
        }
        m_stop_token.store(true);
        m_waker.cancel_next_event();
        m_background_poll.wait();

        // Stopping thread pool results in blocking until all running callbacks are completed
        if(m_pool.running())
        {
            m_pool.stop();
        }
    }

    void event_handling_loop()
    {
        while(!m_stop_token.load())
        {
            const auto event = m_waker.next_event();
            if(event.has_value())
            {
                // Handle event
                auto lock = std::lock_guard<std::mutex>(m_waker_mutex);
                if(auto comp_it = m_completion_handlers.find(event.value()); comp_it != m_completion_handlers.end())
                {
                    m_pool.add_job(
                        [this, completion_handler = std::move(comp_it->second)]()
                        {
                            completion_handler->invoke();
                            m_stop_condition.notify_one();
                        });
                    m_completion_handlers.erase(comp_it);
                }
            }
            // else
            // {
            //     return;
            // }
        }
    }

public:
    static executor& instance()
    {
        static auto handler = executor();
        return handler;
    }

    executor(const executor&) = delete;
    executor& operator=(executor&) = delete;
    executor(executor&&) = delete;
    executor& operator=(executor&&) = delete;

    void run()
    {
        if(m_completion_handlers.empty())
        {
            return;
        }

        // Wait until the handle store is empty. Condition variable notified in remove(...)
        auto mut = std::mutex();
        auto lock = std::unique_lock<std::mutex>(mut);
        m_stop_condition.wait(lock,
            [this]()
            {
                // Check if callback stores are empty
                return m_completion_handlers.empty();
            });
    }

    template <typename CALLBACK_TYPE>
    bool add(const int sock_fd, const event_type type, CALLBACK_TYPE&& callback)
    {
        auto lock = std::lock_guard<std::mutex>(m_waker_mutex);
        m_completion_handlers.insert(std::make_pair(
            std::make_pair(sock_fd, type), std::make_unique<CALLBACK_TYPE>(std::forward<CALLBACK_TYPE>(callback))));
        return m_waker.watch(sock_fd, type);
    }

    bool remove(const int sock_fd, const event_type type)
    {
        auto lock = std::lock_guard<std::mutex>(m_waker_mutex);
        if(const auto it = m_completion_handlers.find(std::make_pair(sock_fd, type)); it != m_completion_handlers.end())
        {
            m_completion_handlers.erase(it);
        }
        return m_waker.unwatch(sock_fd, type);
    }

    void deregister(const int sock_fd)
    {
        const auto fd_range = m_completion_handlers.equal_range(sock_fd);
        for(auto it = fd_range.first; it != fd_range.second;)
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

    void callback_update_socket(const int sock_fd, const base_socket* new_ptr)
    {
        const auto fd_range = m_completion_handlers.equal_range(sock_fd);
        for(auto it = fd_range.first; it != fd_range.second; it++)
        {
            // TODO Check if new_ptr has same type than the old one
            it->second->reset_socket_ptr(new_ptr);
        }
    }
};

} // namespace detail

/// Free function to easily wait until the executor runs out of registered events
inline void async_run()
{
    detail::executor::instance().run();
}

} // namespace net

#endif
