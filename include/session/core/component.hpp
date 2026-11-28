#pragma once

#include <exception>
#include <functional>
#include <optional>
#include <session/handler.hpp>
#include <string>
#include <type_traits>
#include <utility>

namespace session::sqlite {
class Connection;
}
namespace oxen::quic {
class Loop;
class JobQueue;
}  // namespace oxen::quic
namespace session::core {

namespace quic = oxen::quic;

class Core;
struct callbacks;

namespace detail {

    // Reports a component operation that threw, so that `async` does not have to make the logging
    // category reachable from this header.
    void log_component_failure(const std::exception& e);

    /// Internal base class bridge between Core and the various components of core.  This bridge
    /// can be used to allow components to access selected private parts of core, such as the
    /// database, without needing components to be direct friends of Core.
    ///
    /// ## Threading
    ///
    /// **A component's own state is Core's loop's, not the caller's.**  The database underneath is
    /// a thread-safe pool and does not care which thread reads it, but a component is more than
    /// its tables: it caches account key material, holds the config objects, and lazily builds
    /// both.  None of that is synchronised, and Core's loop touches all of it while receiving.  So
    /// anything a component does beyond a self-contained query has to happen on the loop, and
    /// every such method asserts `on_loop()` in a debug build.
    ///
    /// A component method that only reads or writes the database through `conn()` is exempt: the
    /// pool hands the calling thread its own connection, and two threads doing that concurrently
    /// is the arrangement it exists for.  Those methods say so individually.
    ///
    /// `async()` is how a component offers work to a caller on another thread, and mirrors what
    /// `session::client::Client` does with the same `result_function` convention.  Note that
    /// Core has no application dispatcher -- that is Client's -- so a handler passed here runs on
    /// the loop, exactly as `core::callbacks` do.
    class CoreComponent {
      protected:
        friend class core::Core;
        Core& core;

        // Gets a thread-unique database connection from the Core's Database's connection pool. This
        // is unique to the calling thread and must not be used across threads.
        sqlite::Connection conn();

        // Returns the application callbacks registered with Core.
        core::callbacks& cb();

        // Returns the event loop for scheduling async work.
        quic::Loop& loop();

        // Returns Core's job queue, which is where component work belongs.
        //
        // A queue rather than the loop directly so that Core can *cancel* whatever is still
        // outstanding when it goes away, instead of letting those jobs run against components
        // that are already being destroyed.  Stopping the queue does not stop the loop, which
        // Core does not own exclusively once a Network is attached.
        quic::JobQueue& jq();

        // Puts `job` on that queue, running it inline if this already is the loop thread.
        //
        // Out of line, and taking an erased job rather than being a template, so that `async`
        // below can be defined here without this header pulling libquic in front of every
        // consumer of core.hpp.  A `wait_t` overload wants `jq().call_get()` and its return type,
        // so those are written in the component's own translation unit, which includes the loop.
        void enqueue(std::function<void()> job);

        /// True when it is safe for the calling thread to touch this component's own state:
        /// either it is the loop thread, or Core is still being constructed and no other thread
        /// can have reached the component yet.
        ///
        /// Written for `assert(on_loop())` and compiled away with it.
        [[nodiscard]] bool on_loop() const;

        /// Runs `produce` on Core's job queue and reports what it produced to `cb`, or reports the
        /// reason it could not.
        ///
        /// This is what makes "`cb` is invoked exactly once" true for everything except a Core
        /// that is destroyed with the job still queued, which cancels it: the work is database and
        /// config access, which throws on a disk error, and by then the caller's stack is gone --
        /// so the handler they gave us is the only way left to tell them.
        ///
        /// On failure a handler taking a value is given a default-constructed one alongside the
        /// error, which it is being told not to read.
        template <typename Produce, typename Cb>
        void async(Produce produce, Cb cb);

        explicit CoreComponent(Core& core);

        // Default component `init()` does nothing; classes can override this if they want to be
        // called after database migrations are complete, but still during the parent Core
        // construction.  This will be called on each CoreComponent-derived member of Core, in the
        // same order that those members were constructed (i.e. class declaration order).
        virtual void init() {}
    };

    template <typename Produce, typename Cb>
    void CoreComponent::async(Produce produce, Cb cb) {
        enqueue([produce = std::move(produce), cb = std::move(cb)]() mutable {
            using Result = decltype(produce());
            try {
                if constexpr (std::is_void_v<Result>) {
                    produce();
                    if (cb)
                        cb(Expected<void>{});
                } else {
                    auto result = produce();
                    if (cb)
                        cb(Expected<Result>{std::move(result)});
                }
            } catch (const std::exception& e) {
                log_component_failure(e);
                if (cb)
                    cb(Expected<Result>{unexpected{error_from(e)}});
            }
        });
    }

}  // namespace detail

}  // namespace session::core
