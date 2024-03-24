#ifndef SOCKETWRAPPER_NET_INTERNAL_THREADPOOL_HPP
#define SOCKETWRAPPER_NET_INTERNAL_THREADPOOL_HPP

#include <condition_variable>
#include <future>
#include <mutex>
#include <queue>
#include <thread>
#include <vector>

namespace net {

namespace detail {

/// Thread pool
class thread_pool
{
    void destroy_worker()
    {
        {
            auto job_lock = std::lock_guard(m_job_mut);
            m_running = false;
        }
        m_job_available.notify_all();

        for (auto& worker : m_workers)
        {
            worker.join();
        }
        m_workers.clear();
    }

    void worker()
    {
        auto worker_lock = std::unique_lock<std::mutex>(m_job_mut);
        while (true)
        {
            worker_lock.unlock();
            if (m_paused && m_queue.empty())
            {
                m_job_done.notify_all();
            }

            worker_lock.lock();
            m_job_available.wait(worker_lock, [this]() { return !m_running || !m_queue.empty(); });

            if (!m_running)
            {
                break;
            }

            m_busy_threads++;
            {
                auto current_task = std::move(m_queue.front());
                m_queue.pop();
                worker_lock.unlock();
                current_task();
                worker_lock.lock();
            }
            m_busy_threads--;
        }
    }

    std::queue<std::packaged_task<void()>> m_queue{};

    std::vector<std::thread> m_workers{};

    std::condition_variable m_job_available{};

    std::condition_variable m_job_done{};

    mutable std::mutex m_job_mut{};

    size_t m_pool_size;

    size_t m_busy_threads{0};

    bool m_running{true};

    bool m_paused{false};

public:
    thread_pool(const size_t size)
        : m_pool_size{size}
    {
        m_workers.reserve(m_pool_size);
        for (size_t i = 0; i < m_pool_size; ++i)
        {
            m_workers.emplace_back(&thread_pool::worker, this);
        }
    }

    ~thread_pool()
    {
        destroy_worker();
    }

    bool queue_empty() const
    {
        auto lock = std::lock_guard(m_job_mut);
        return m_queue.empty();
    }

    bool busy() const
    {
        auto lock = std::lock_guard(m_job_mut);
        return m_busy_threads != 0;
    }

    void flush()
    {
        // Wait until the queue is empty and all worker threads are done
        auto job_lock = std::unique_lock(m_job_mut);
        m_paused = true;
        m_job_done.wait(job_lock, [this]() { return m_busy_threads == 0 && m_queue.empty(); });
        m_paused = false;
    }

    template <typename job_type>
    void add_job(job_type&& job_task)
    {
        if (!m_running)
        {
            return;
        }

        // TODO Return a stop token that can be used to stop/cancel a job from the outside
        {
            const auto queue_lock = std::lock_guard<std::mutex>(m_job_mut);
            m_queue.emplace(std::forward<job_type>(job_task));
        }
        m_job_available.notify_one();
    }
};

} // namespace detail

} // namespace net

#endif
