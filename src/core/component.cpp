#include <oxen/log.hpp>
#include <oxen/quic/loop.hpp>
#include <session/core.hpp>
#include <session/core/component.hpp>
#include <session/sqlite.hpp>

namespace session::core::detail {

namespace log = oxen::log;

static auto cat = log::Cat("core.comp");

void log_component_failure(const std::exception& e) {
    log::warning(cat, "Component operation failed: {}", e.what());
}

sqlite::Connection CoreComponent::conn() {
    return core.db.conn();
}

core::callbacks& CoreComponent::cb() {
    return core.callbacks;
}

quic::Loop& CoreComponent::loop() {
    return core._loop;
}

quic::JobQueue& CoreComponent::jq() {
    return core._jq;
}

void CoreComponent::enqueue(std::function<void()> job) {
    core._jq.call(std::move(job));
}

bool CoreComponent::on_loop() const {
    // Before the end of Core's constructor there is no other thread that could have reached a
    // component: the loop runs nothing of ours until `init()` has finished, and the caller
    // constructing Core is the only one holding it.  Component `init()` therefore runs off the
    // loop legitimately, and asserting otherwise would fire on every open.
    return !core._constructed || core._loop.inside();
}

CoreComponent::CoreComponent(Core& core) : core{core} {
    core.register_comp_init(this);
}

}  // namespace session::core::detail
