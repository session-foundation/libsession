#include "session/network/request_queue.hpp"

#include <event2/event.h>
#include <fmt/ranges.h>

#include <oxen/log.hpp>
#include <oxen/log/format.hpp>
#include <oxen/quic/utils.hpp>

using namespace oxen;
using namespace oxen::log::literals;

namespace session::network::detail {

namespace {
    auto cat = oxen::log::Cat("request_queue");
}

RequestQueue::~RequestQueue() {
    // Runs whatever adds are already queued before cancelling them below, so that a request that
    // arrived just before this destructor still gets told it is not going to be sent.  Dropping
    // those jobs instead would drop their callbacks with them, and the caller would hear nothing.
    _jq.call_get([] {});
    _jq.stop();

    // The timeout event is the loop's to fire and reaches `this`, so it has to be taken away on the
    // loop thread rather than from here.  The cancellations go in the same job because that is
    // where they have always been called from.
    _loop.call_get([this] {
        _timeout.reset();

        for (auto& [id, request_pair] : _requests) {
            auto& [req, callback] = request_pair;

            try {
                callback(
                        false,
                        false,
                        -1,
                        {content_type_plain_text},
                        "Request cancelled: networking system is shutting down");
            } catch (...) { /* Ignore exceptions during shutdown */
            }
        }
    });
}

void RequestQueue::add(Request request, network_response_callback_t callback) {
    _jq.call([this, req = std::move(request), cb = std::move(callback)]() mutable {
        const auto req_id = req.request_id;
        const auto creation_time = req.creation_time;
        const auto timeout = req.overall_timeout;
        _requests.emplace(req_id, std::make_pair(std::move(req), std::move(cb)));
        _queue.emplace_back(req_id);

        if (timeout) {
            auto expiry = creation_time + *timeout;

            // We hint at the end because it is an extremely common pattern that you use the same
            // timeout for all (or most) requests in which case each new request timeout *does* land
            // at the end.
            _req_expiries.emplace_hint(_req_expiries.end(), expiry, req_id);

            // If the expiry entry landed at the beginning of the map -- either because it was
            // empty, or because this has a shorter timeout than what's already in there -- then we
            // need to (re)schedule the event to this request's timeout.
            if (_req_expiries.begin()->second == req_id)
                update_timeout();
        }
    });
}

void RequestQueue::add_front(std::pair<Request, network_response_callback_t> req_pair) {
    _jq.call([this, pair = std::move(req_pair)] {
        const auto req_id = pair.first.request_id;
        const auto creation_time = pair.first.creation_time;
        const auto timeout = pair.first.overall_timeout;
        _requests.emplace(req_id, std::move(pair));
        _queue.emplace_front(req_id);

        if (timeout) {
            auto expiry = creation_time + *timeout;

            // We hint at the end because it is an extremely common pattern that you use the same
            // timeout for all (or most) requests in which case each new request timeout *does* land
            // at the end.
            _req_expiries.emplace_hint(_req_expiries.end(), expiry, req_id);

            // If the expiry entry landed at the beginning of the map -- either because it was
            // empty, or because this has a shorter timeout than what's already in there -- then we
            // need to (re)schedule the event to this request's timeout.
            if (_req_expiries.begin()->second == req_id)
                update_timeout();
        }
    });
}

std::deque<std::pair<Request, network_response_callback_t>> RequestQueue::pop_all() {
    return _jq.call_get([this] {
        std::deque<std::pair<Request, network_response_callback_t>> popped_items;

        for (const auto& id : _queue) {
            auto it = _requests.find(id);

            if (it != _requests.end()) {
                popped_items.push_back(std::move(it->second));
                _requests.erase(it);
            }
        }

        _queue.clear();
        _requests.clear();
        _req_expiries.clear();
        update_timeout();

        return popped_items;
    });
}

void RequestQueue::check_timeouts(std::optional<std::chrono::steady_clock::time_point> now) {
    std::list<std::pair<Request, network_response_callback_t>> expired;
    auto it = _req_expiries.begin();
    for (; it != _req_expiries.end() && (!now || it->first <= *now); ++it) {
        auto id = it->second;

        if (auto reqit = _requests.find(id); reqit != _requests.end()) {
            expired.push_back(std::move(reqit->second));
            _requests.erase(reqit);
        }
    }
    _req_expiries.erase(_req_expiries.begin(), it);

    for (auto& [req, callback] : expired) {
        try {
            callback(
                    false,
                    true,
                    ERROR_BUILD_TIMEOUT,
                    {content_type_plain_text},
                    "Timed out while in build queue.");
        } catch (const std::exception& e) {
            log::error(cat, "Uncaught exception from timeout response handler: {}", e.what());
        }
    }
}

void RequestQueue::update_timeout() {
    if (_req_expiries.empty()) {
        if (_timeout)
            event_del(_timeout.get());
        return;
    }

    if (!_timeout) {
        // If this is the first request timeout then set up the timeout event timer:
        _timeout.reset(event_new(
                _loop.get_event_base(),
                -1,          // Not attached to an actual socket
                EV_TIMEOUT,  // Stays active (i.e. repeats) once fired
                [](evutil_socket_t, short, void* self) {
                    auto* me = static_cast<RequestQueue*>(self);
                    me->check_timeouts(std::chrono::steady_clock::now());
                    me->update_timeout();
                },
                this));
    }

    auto expires_in = std::chrono::ceil<std::chrono::microseconds>(
            _req_expiries.begin()->first - std::chrono::steady_clock::now());
    if (expires_in < 0us)
        expires_in = 0us;
#ifdef _WIN32
    using suseconds_t = long;
#endif
    timeval exp_interval{
            .tv_sec = static_cast<time_t>(expires_in / 1s),
            .tv_usec = static_cast<suseconds_t>((expires_in % 1s).count())};

    event_add(_timeout.get(), &exp_interval);
}

}  // namespace session::network::detail
