#include "session/network/session_network_types.hpp"

#include <oxen/log.hpp>
#include <oxen/log/format.hpp>

#include "session/random.hpp"

using namespace oxen;
using namespace oxen::log::literals;

namespace session::network {

Request::Request(
        std::string request_id,
        network_destination destination,
        std::string endpoint,
        std::optional<std::vector<unsigned char>> body,
        RequestCategory category,
        std::chrono::milliseconds request_timeout,
        std::optional<std::chrono::milliseconds> overall_timeout,
        std::optional<uint8_t> desired_path_index,
        RequestDetails details) :
        request_id{std::move(request_id)},
        destination{std::move(destination)},
        endpoint{std::move(endpoint)},
        body{std::move(body)},
        category{std::move(category)},
        request_timeout{std::move(request_timeout)},
        overall_timeout{std::move(overall_timeout)},
        desired_path_index{std::move(desired_path_index)},
        details{details} {}

Request::Request(
        network_destination destination,
        std::string endpoint,
        std::optional<std::vector<unsigned char>> body,
        RequestCategory category,
        std::chrono::milliseconds request_timeout,
        std::optional<std::chrono::milliseconds> overall_timeout,
        std::optional<uint8_t> desired_path_index,
        std::optional<std::string> request_id,
        RequestDetails details) :
        request_id{std::move(request_id.value_or(random::unique_id("R")))},
        destination{std::move(destination)},
        endpoint{std::move(endpoint)},
        body{std::move(body)},
        category{std::move(category)},
        request_timeout{std::move(request_timeout)},
        overall_timeout{std::move(overall_timeout)},
        desired_path_index{std::move(desired_path_index)},
        details{details} {}

static const std::unordered_map<std::string_view, std::pair<int16_t, bool>> error_map = {
        {"400 Bad Request", {400, false}},
        {"401 Unauthorized", {401, false}},
        {"403 Forbidden", {403, false}},
        {"404 Not Found", {404, false}},
        {"405 Method Not Allowed", {405, false}},
        {"406 Not Acceptable", {406, false}},
        {"408 Request Timeout", {408, false}},
        {"500 Internal Server Error", {500, false}},
        {"502 Bad Gateway", {502, false}},
        {"503 Service Unavailable", {503, false}},
        {"504 Gateway Timeout", {504, true}},
};

std::optional<std::pair<int16_t, bool>> response::parse_text_error(std::string_view body) {

    for (const auto& [prefix, result] : error_map)
        if (body.starts_with(prefix))
            return result;

    return std::nullopt;
}

namespace {
    inline auto cat = log::Cat("network");

    const nlohmann::json* field(
            const nlohmann::json& j,
            std::string_view key,
            bool (nlohmann::json::*is_kind)() const noexcept) {
        auto it = j.find(key);
        return it != j.end() && ((*it).*is_kind)() ? &*it : nullptr;
    }

    std::optional<x25519_pubkey> account_in(const nlohmann::json& obj) {
        auto pk = field(obj, "pubkey", &nlohmann::json::is_string);
        if (!pk)
            return std::nullopt;

        // Prefixed with the network id, except on testnet
        auto hex = pk->get<std::string_view>();
        if (hex.size() == 66)
            hex.remove_prefix(2);
        return x25519_pubkey::maybe_from_hex(hex);
    }

    // Only the pubkeys: the rest of each record is contact information we deliberately don't read,
    // so a redirect can't put us in touch with anything the pool hasn't already told us about.
    std::vector<ed25519_pubkey> redirect_keys(const nlohmann::json& body) {
        std::vector<ed25519_pubkey> keys;

        if (auto snodes = field(body, "snodes", &nlohmann::json::is_array))
            for (const auto& snode : *snodes)
                if (auto pk = field(snode, "pubkey_ed25519", &nlohmann::json::is_string))
                    if (auto key = ed25519_pubkey::maybe_from_hex(pk->get<std::string_view>()))
                        keys.push_back(*key);

        return keys;
    }

    std::optional<x25519_pubkey> account_by_position(
            std::span<const std::optional<x25519_pubkey>> accounts, size_t index) {
        if (accounts.size() == 1)
            return accounts.front();
        return index < accounts.size() ? accounts[index] : std::nullopt;
    }
}  // namespace

int16_t response::undecrypted_status(int16_t status) {
    switch (status) {
        case ERROR_NOT_ACCEPTABLE:
        case ERROR_MISDIRECTED_REQUEST:
        case ERROR_TOO_EARLY: return ERROR_UNAUTHENTICATED_RESPONSE;
        default: return status;
    }
}

std::optional<int16_t> response::find_uniform_batch_error(std::string_view body) {
    try {
        return uniform_batch_error(nlohmann::json::parse(body));
    } catch (...) { /* Do nothing */
    }

    return std::nullopt;
}

std::optional<int16_t> response::uniform_batch_error(const nlohmann::json& json) {
    std::optional<int16_t> uniform;

    // A response that isn't a batch has no per-result codes, so its own status stands
    for (const auto& sub : subresponses(json)) {
        if (!sub.code || (*sub.code >= 200 && *sub.code <= 299))
            return std::nullopt;
        if (uniform && *uniform != *sub.code)
            return std::nullopt;
        uniform = sub.code;
    }

    return uniform;
}

std::vector<response::subresponse> response::subresponses(const nlohmann::json& json) {
    auto results = field(json, "results", &nlohmann::json::is_array);
    if (!results)
        return {{std::nullopt, json.is_object() ? &json : nullptr}};

    std::vector<subresponse> subs;
    subs.reserve(results->size());

    for (const auto& result : *results) {
        auto& sub = subs.emplace_back();
        if (auto code = field(result, "code", &nlohmann::json::is_number))
            sub.code = code->get<int16_t>();
        sub.body = field(result, "body", &nlohmann::json::is_object);
    }

    return subs;
}

std::optional<std::vector<std::optional<x25519_pubkey>>> batch_request_accounts(
        std::string_view endpoint,
        std::span<const unsigned char> body,
        std::optional<x25519_pubkey> fallback) {
    if (endpoint != "batch" && endpoint != "sequence")
        return std::nullopt;

    auto json = nlohmann::json::parse(body.begin(), body.end(), nullptr, false);
    auto requests = field(json, "requests", &nlohmann::json::is_array);
    if (!requests)
        return std::nullopt;

    std::vector<std::optional<x25519_pubkey>> accounts;
    accounts.reserve(requests->size());

    for (const auto& req : *requests) {
        auto& account = accounts.emplace_back();
        if (auto params = field(req, "params", &nlohmann::json::is_object))
            account = account_in(*params);
        if (!account)
            account = fallback;
    }

    return accounts;
}

response::swarm_rejections response::find_swarm_rejections(
        const nlohmann::json* json,
        int16_t status_code,
        std::span<const std::optional<x25519_pubkey>> accounts) {
    swarm_rejections result;

    // A body that isn't JSON still leaves the response's own status to act on, just with no
    // redirect to go with it
    auto subs = json ? subresponses(*json) : std::vector<subresponse>{{}};

    for (size_t i = 0; i < subs.size(); ++i) {
        const auto& [code, sub_body] = subs[i];
        if (code.value_or(status_code) != ERROR_MISDIRECTED_REQUEST)
            continue;

        // Attributed by position in our own request, never by the account the 421 names: that is
        // the responding node's word, and taking it would let any node we talk to redirect any
        // account it likes - not just the ones it was asked about - onto nodes of its choosing
        auto account = account_by_position(accounts, i);
        if (!account) {
            result.unattributed = true;
            continue;
        }

        if (auto echoed = sub_body ? account_in(*sub_body) : std::nullopt;
            echoed && *echoed != *account) {
            log::warning(
                    cat,
                    "Ignoring a 421 for {} that names {} as the rejected account.",
                    account->hex(),
                    echoed->hex());
            result.unattributed = true;
            continue;
        }

        // Several sub-requests for one account (a retrieve per namespace, say) all name its swarm,
        // so the first is as good as any
        if (auto [it, inserted] = result.accounts.try_emplace(*account); inserted && sub_body)
            it->second = redirect_keys(*sub_body);
    }

    return result;
}

}  // namespace session::network
