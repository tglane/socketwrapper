#ifndef SOCKETWRAPPER_NET_INTERNAL_THREADPOOL_HPP
#define SOCKETWRAPPER_NET_INTERNAL_THREADPOOL_HPP

#include <vector>
#include <queue>
#include <thread>
#include <mutex>
#include <condition_variable>
#include <functional>

namespace net {

namespace detail {

/// Thread pool
class thread_pool
{
public:

    thread_pool()
        : m_pool_size {std::thread::hardware_concurrency()}
    {
        m_workers.reserve(m_pool_size);
        for(size_t i = 0; i < m_pool_size; ++i)
            m_workers.emplace_back(&thread_pool::loop, this);
    }

    thread_pool(size_t size)
        : m_pool_size {size}
    {
        m_workers.reserve(m_pool_size);
        for(size_t i = 0; i < m_pool_size; ++i)
            m_workers.emplace_back(&thread_pool::loop, this);
    }

    ~thread_pool()
    {
        if(m_running)
            stop();
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
            return;
        m_running = false;

        m_cv.notify_all();

        for(auto& worker : m_workers)
            worker.join();
        m_workers.clear();
    }

    void add_job(std::function<void()> func)
    {
        {
            const std::lock_guard<std::mutex> lock {m_qmutex};
            m_queue.push(std::move(func));
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
        std::function<void()> func;

        while(m_running || !m_queue.empty())
        {
            {
                std::unique_lock<std::mutex> lock {m_qmutex};
                m_cv.wait(lock, [this]() { return (!m_queue.empty() || !m_running); });
                if(!m_running && m_queue.empty())
                    return;
                else if(m_queue.empty())
                    continue;

                func = m_queue.front();
                m_queue.pop();
            }

            func();
        }
    }

    bool m_running = true;

    size_t m_pool_size;

    std::vector<std::thread> m_workers;

    std::queue<std::function<void()>> m_queue;

    std::mutex m_qmutex;

    std::condition_variable m_cv;

};

} // namespace detail

} // namespace net

#endif
