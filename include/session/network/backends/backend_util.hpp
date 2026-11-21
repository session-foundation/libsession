#pragma once

#include <fmt/format.h>

#include <iostream>
#include <string_view>
#include <vector>
namespace session::network::backends {

const std::string_view FRAGMENT_PUBKEY = "p";
const std::string_view FRAGMENT_STREAM_ENCRYPTION = "d";

struct MatchedEndpoint {
    std::string_view base;  // everything before the pattern match (e.g. "https://example.com")
    std::vector<std::string_view> captures;
};

static std::optional<MatchedEndpoint> match_endpoint(
        std::string_view pattern, std::string_view input) {
    if (input.empty())
        return {};

    auto first_placeholder = pattern.find("{}");
    auto static_prefix = fmt::format("/{}", pattern.substr(0, first_placeholder));

    auto pattern_start = input.find(static_prefix);
    if (pattern_start == std::string_view::npos)
        return std::nullopt;

    MatchedEndpoint result;
    result.base = input.substr(0, pattern_start);

    // Skip leading '/' if present, otherwise start from the pattern directly
    auto remaining = input.substr(pattern_start);
    if (!remaining.empty() && remaining[0] == '/')
        remaining = remaining.substr(1);

    while (!pattern.empty()) {
        auto placeholder = pattern.find("{}");
        auto literal = pattern.substr(0, placeholder);

        if (!remaining.starts_with(literal))
            return std::nullopt;

        remaining = remaining.substr(literal.size());

        if (placeholder == std::string_view::npos)
            break;

        pattern = pattern.substr(placeholder + 2);

        // Capture up to the next literal segment (or end of path segment if pattern is exhausted)
        auto next_literal = pattern.substr(0, pattern.find("{}"));
        auto capture_end = next_literal.empty() ? std::min(remaining.find('#'), remaining.find('?'))
                                                : remaining.find(next_literal);
        if (capture_end == std::string_view::npos && !next_literal.empty())
            return std::nullopt;

        // If no fragment/query, capture to end of string
        if (capture_end == std::string_view::npos)
            capture_end = remaining.size();

        auto capture = remaining.substr(0, capture_end);

        if (!capture.empty() && capture.back() == '/')
            capture.remove_suffix(1);

        result.captures.push_back(capture);
        remaining = remaining.substr(capture_end);
    }

    return result;
}

}  // namespace session::network::backends
