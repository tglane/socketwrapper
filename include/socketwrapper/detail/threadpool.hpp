#ifndef SOCKETWRAPPER_NET_INTERNAL_THREADPOOL_HPP
#define SOCKETWRAPPER_NET_INTERNAL_THREADPOOL_HPP

#include "callbacks.hpp"

#include <condition_variable>
#include <functional>
#include <future>
#include <mutex>
#include <queue>
#include <thread>
#include <vector>

namespace net {

namespace detail {

/// Forward declarations
class async_context;

/// Thread pool
class thread_pool
{
public:
    thread_pool(size_t size)
        : m_pool_size{size}
    {
        m_workers.reserve(m_pool_size);
        for(size_t i = 0; i < m_pool_size; ++i)
        {
            m_workers.emplace_back(&thread_pool::loop, this);
        }
    }

    ~thread_pool()
    {
        if(m_running)
        {
            stop();
        }
    }

    bool running() const
    {
        return m_running;
    }

    size_t pool_size() const
    {
        return m_pool_size;
    }

    void stop()
    {
        if(!m_running)
        {
            return;
        }
        m_running = false;

        m_cv.notify_all();

        for(auto& worker : m_workers)
        {
            worker.join();
        }
        m_workers.clear();
    }

    template <typename USER_JOB>
    void add_job(USER_JOB&& job_task)
    {
        // TODO Return a stop token that can be used to stop/cancel a job from the outside
        {
            const auto queue_lock = std::lock_guard<std::mutex>(m_qmutex);
            m_queue.push(std::packaged_task<void()>(std::forward<USER_JOB>(job_task)));
        }
        m_cv.notify_one();
    }

    void flush()
    {
        // TODO Block until all currently scheduled tasks are executed
    }

private:
    void loop()
    {
        std::packaged_task<void()> curr_task;
        while(m_running || !m_queue.empty())
        {
            {
                auto queue_lock = std::unique_lock<std::mutex>(m_qmutex);
                m_cv.wait(queue_lock, [this]() { return (!m_queue.empty() || !m_running); });
                if(!m_running && m_queue.empty())
                {
                    return;
                }
                else if(m_queue.empty())
                {
                    continue;
                }

                curr_task = std::move(m_queue.front());
                m_queue.pop();
            }

            curr_task();
        }
    }

    bool m_running = true;

    size_t m_pool_size;

    std::vector<std::thread> m_workers;

    std::queue<std::packaged_task<void()>> m_queue;

    std::mutex m_qmutex;

    std::condition_variable m_cv;
};

} // namespace detail

} // namespace net

#endif
