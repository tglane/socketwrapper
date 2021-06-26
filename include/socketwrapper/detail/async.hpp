#ifndef SOCKETWRAPPER_NET_INTERNAL_ASYNC_HPP
#define SOCKETWRAPPER_NET_INTERNAL_ASYNC_HPP

#include "callbacks.hpp"
#include "threadpool.hpp"

#include <memory>
#include <array>
#include <map>
#include <future>
#include <mutex>
#include <condition_variable>

#include <unistd.h>
#include <sys/epoll.h>

namespace net {

namespace detail {

/// Class to manage all asynchronous socket io operations
class async_context
{

    enum context_control
    {
        EXIT_LOOP = 1,
        RELOAD_FD_SET = 2
    };

    /// Struct to store events and corresponding callbacks before they are handled by the <thread_pool>
    struct context_item
    {
        epoll_event event;
        async_callback callback;
    };

    /// No op callback used to add the pipe file descriptor to manage the async_context
    //  [Gets never called]
    struct no_op_callback : public abstract_socket_callback
    {
        void operator()() const override
        {}
    };

public:

    enum event_type
    {
        READ = EPOLLIN,
        WRITE = EPOLLOUT
    };

    static async_context& instance()
    {
        static async_context handler;
        return handler;
    }

    async_context(const async_context&) = delete;
    async_context& operator=(async_context&) = delete;
    async_context(async_context&&) = delete;
    async_context& operator=(async_context&&) = delete;

    void run()
    {
        if(m_store.size() == 1)
            return;

        // Wait until the handle store is empty. Condition variable notified in remove(...)
        std::mutex mut;
        std::unique_lock<std::mutex> lock {mut};
        m_condition.wait(lock, [this]() {
            return m_store.size() == 1;
        });
    }

    template<typename CALLBACK_TYPE>
    bool add(const int sock_fd, const event_type type, CALLBACK_TYPE&& callback)
    {
        if(const auto [inserted, success] = m_store.insert_or_assign(
                sock_fd,
                context_item {epoll_event {}, std::forward<CALLBACK_TYPE>(callback)}
        ); success)
        {
            auto& item = inserted->second;
            item.event.events = type | EPOLLET;
            item.event.data.fd = sock_fd;
            if(::epoll_ctl(m_epfd, EPOLL_CTL_ADD, sock_fd, &(item.event)) == -1)
            {
                m_store.erase(inserted);
                return false;
            }

            // item.callback = std::forward<CALLBACK_TYPE>(callback);

            // Restart loop with updated fd set
            const uint8_t control_byte = RELOAD_FD_SET;
            ::write(m_pipe_fds[1], &control_byte, 1);

            return true;
        }
        return false;
    }

    bool remove(const int sock_fd)
    {
        if(const auto& it = m_store.find(sock_fd); it != m_store.end())
        {
            if(::epoll_ctl(m_epfd, EPOLL_CTL_DEL, sock_fd, nullptr) == -1)
                return false;

            m_store.erase(it);

            // Restart loop with updated fd set
            const uint8_t control_byte = RELOAD_FD_SET;
            ::write(m_pipe_fds[1], &control_byte, 1);

            return true;
        }
        return false;
    }

    bool socket_registered(const int sock_fd) const
    {
        if(const auto& it = m_store.find(sock_fd); it != m_store.end())
            return true;
        else
            return false;
    }

    bool callback_update_socket(const int sock_fd, const base_socket* new_ptr)
    {
        if(const auto& it = m_store.find(sock_fd); it != m_store.end())
        {
            // TODO Check if new_ptr has same type than the old one
            it->second.callback.reset_socket_ptr(new_ptr);
            return true;
        }
        return false;
    }

private:

    async_context()
    {
        if(m_epfd = ::epoll_create(1); m_epfd == -1)
            throw std::runtime_error {"Failed to create epoll instance when instantiating message_notifier."};

        // Create pipe to stop select and add it to m_fds
        if(::pipe(m_pipe_fds.data()) < 0)
            throw std::runtime_error {"Failed to create pipe when instantiating class message_notifier."};

        // Add the pipe to the epoll monitoring set
        auto [pipe_item_it, success] = m_store.emplace(m_pipe_fds[0],
            context_item {epoll_event{}, no_op_callback {}});
        pipe_item_it->second.event.events = EPOLLIN;
        pipe_item_it->second.event.data.fd = m_pipe_fds[0];
        ::epoll_ctl(m_epfd, EPOLL_CTL_ADD, m_pipe_fds[0], &(pipe_item_it->second.event));

        m_context_holder = std::async(std::launch::async, &async_context::context_loop, this);
    }

    ~async_context()
    {
        // Send stop signal to epoll loop to exit background task
        const uint8_t stop_byte = EXIT_LOOP;
        ::write(m_pipe_fds[1], &stop_byte, 1);

        m_context_holder.get();

        ::close(m_pipe_fds[0]);
        ::close(m_pipe_fds[1]);
        ::close(m_epfd);

        // Stopping thread pool results in blocking until all running callbacks are completed
        if(m_pool.running())
             m_pool.stop();
    }

    void context_loop()
    {
        std::array<epoll_event, 64> ready_set;

        while(true)
        {
            const int num_ready = ::epoll_wait(m_epfd, ready_set.data(), 64, -1);
            if(num_ready < 0)
                continue;

            for(int i = 0; i < num_ready; ++i)
            {
                if(ready_set[i].data.fd == m_pipe_fds[0])
                {
                    // Stop signal to end the loop from the destructor
                    uint8_t byte {0};
                    ::read(ready_set[i].data.fd, &byte, 1);
                    if(byte == EXIT_LOOP)
                        return;
                }
                else if(ready_set[i].events & EPOLLIN || ready_set[i].events & EPOLLOUT)
                {
                    // Run callback on receiving socket and deregister this socket from context afterwards
                    if(const auto& ev_it = m_store.find(ready_set[i].data.fd); ev_it != m_store.end())
                    {
                        // Get the callback registered for the event and remove the event from the context
                        m_pool.add_job([this, callback = std::move(ev_it->second.callback)]() {
                            try {
                                callback();
                            } catch(std::runtime_error& rt) {}

                            if(m_store.size() == 1)
                                m_condition.notify_one();
                        });

                        this->remove(ev_it->first);
                    }
                }
            }
        }
    }

    int m_epfd {};

    std::array<int, 2> m_pipe_fds {};

    std::future<void> m_context_holder {};

    std::map<int, context_item> m_store {};

    thread_pool m_pool {};

    std::condition_variable m_condition;

};

} // namespace async

} // namespace net

#endif
