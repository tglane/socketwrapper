#ifndef SOCKETWRAPPER_NET_INTERNAL_MESSAGE_NOTIFIER_HPP
#define SOCKETWRAPPER_NET_INTERNAL_MESSAGE_NOTIFIER_HPP

#if defined(__FreeBSD__) || defined(__APPLE__) || defined(__OpenBSD__) || defined(__NetBSD__)
#include "event_notifier_kqueue.hpp"
#elif defined(__linux__)
#include "event_notifier_epoll.hpp"
#endif

namespace net {

namespace detail {

#if defined(__FreeBSD__) || defined(__APPLE__) || defined(__OpenBSD__) || defined(__NetBSD__)
using event_notifier = event_notifier_kqueue;
#elif defined(__linux__)
using event_notifier = event_notifier_epoll;
#endif

} // namespace detail

} // namespace net

#endif
