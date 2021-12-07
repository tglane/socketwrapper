#ifndef SOCKETWRAPPER_NET_INTERNAL_MESSAGE_NOTIFIER_HPP
#define SOCKETWRAPPER_NET_INTERNAL_MESSAGE_NOTIFIER_HPP

#include <array>
#include <future>
#include <map>

#include <sys/epoll.h>
#include <unistd.h>

namespace net {

namespace detail {

/// Notifies on receive event of a socket via a given std::condition_variable
class message_notifier
{
public:
    message_notifier(const message_notifier&) = delete;
    message_notifier& operator=(const message_notifier&) = delete;
    message_notifier(message_notifier&&) = delete;
    message_notifier& operator=(const message_notifier&&) = delete;

    static message_notifier& instance()
    {
        static message_notifier notifier;
        return notifier;
    }

    bool add(int sock_fd, std::condition_variable* cv)
    {
        if(auto [inserted, success] =
                m_store.emplace(sock_fd, std::pair<std::condition_variable*, epoll_event>{cv, epoll_event{}});
            success)
        {
            auto& ev = inserted->second.second;

            ev.events = EPOLLIN;
            ev.data.fd = sock_fd;
            ::epoll_ctl(m_epfd, EPOLL_CTL_ADD, sock_fd, &ev);
            return true;
        }
        return false;
    }

    bool remove(int sock_fd)
    {
        if(const auto& it = m_store.find(sock_fd); it != m_store.end())
        {
            auto& ev = it->second.second;

            ::epoll_ctl(m_epfd, EPOLL_CTL_DEL, sock_fd, &ev);
            m_store.erase(it);
            return true;
        }
        return false;
    }

private:
    message_notifier()
    {
        if(m_epfd = ::epoll_create(1); m_epfd == -1)
            throw std::runtime_error{"Failed to create epoll instance when instantiating message_notifier."};

        // Create pipe to stop select and add it to m_fds
        if(::pipe(m_pipe_fds.data()) < 0)
            throw std::runtime_error{"Failed to create pipe when instantiating class message_notifier."};

        // Add the pipe to the epoll monitoring set
        m_pipe_event.events = EPOLLIN;
        m_pipe_event.data.fd = m_pipe_fds[0];
        ::epoll_ctl(m_epfd, EPOLL_CTL_ADD, m_pipe_fds[0], &m_pipe_event);

        m_future = std::async(std::launch::async,
            [this]()
            {
                std::array<epoll_event, 64> ready_set;

                while(true)
                {
                    int num_ready = ::epoll_wait(this->m_epfd, ready_set.data(), 64, 100);
                    for(int i = 0; i < num_ready; ++i)
                    {
                        if(ready_set[i].data.fd == this->m_pipe_fds[0])
                        {
                            // Stop signal via destructor
                            return;
                        }
                        else if(ready_set[i].events & EPOLLIN)
                        {
                            // Data ready to read on socket -> notify
                            if(const auto& it = this->m_store.find(ready_set[i].data.fd);
                                it != this->m_store.end() && it->second.first != nullptr)
                                it->second.first->notify_one();
                        }
                    }
                }
            });
    }

    ~message_notifier()
    {
        // Send stop signal to epoll loop to exit background task
        char stop_byte = 0;
        ::write(m_pipe_fds[1], &stop_byte, 1);

        m_future.get();

        ::close(m_pipe_fds[0]);
        ::close(m_pipe_fds[1]);
    }

    int m_epfd;

    epoll_event m_pipe_event;
    std::array<int, 2> m_pipe_fds;

    std::future<void> m_future;

    std::map<int, std::pair<std::condition_variable*, epoll_event>> m_store;
};

} // namespace detail

} // namespace net

#endif
