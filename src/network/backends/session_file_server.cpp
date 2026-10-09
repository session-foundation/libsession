#include "session/network/backends/session_file_server.hpp"

#include <fmt/ranges.h>
#include <oxenc/base64.h>

#include <oxen/log.hpp>
#include <oxen/log/format.hpp>

#include "../session_network_internal.hpp"
#include "session/blinding.hpp"
#include "session/network/backends/backend_util.hpp"
#include "session/network/backends/session_file_server.h"
#include "session/network/key_types.hpp"
#include "session/random.hpp"
#include "session/util.hpp"

#if defined(__APPLE__) || !defined(__cpp_lib_chrono) || __cpp_lib_chrono < 201907L || \
        (defined(_LIBCPP_VERSION) && _LIBCPP_VERSION < 190000)
#include <date/date.h>
namespace chrono_for_parsing = date;
#else
namespace chrono_for_parsing = std::chrono;
#endif

using namespace oxen;
using namespace std::literals;
using namespace oxen::log::literals;

namespace session::network::file_server {

const config::FileServer DEFAULT_CONFIG = {
        .scheme = "http",
        .host = "filev2.getsession.org",
        .port = 80,
        // ED25519. `p=` in a download url carries the Ed form on every client, and the X25519 form
        // for onion requests is derived from it.
        //
        // NOT the file server's X25519-only key (`da21e1d886c6...ee59`), which cannot be used here:
        // it has no Ed private key and cannot be given one, since deriving Ed from X would mean
        // reversing a hash. A file server has to publish a real Ed keypair to be addressable this
        // way.
        .pubkey_hex = "b8eef9821445ae16e2e97ef8aa6fe782fd11ad5253cd6723b281341dba22e371",
        .max_file_size = 10'000'000};

constexpr std::string_view HEADER_CONTENT_TYPE = "Content-Type";
constexpr std::string_view HEADER_CONTENT_DISPOSITION = "Content-Disposition";
constexpr std::string_view HEADER_PUBKEY = "X-FS-Pubkey";
constexpr std::string_view HEADER_TIMESTAMP = "X-FS-Timestamp";
constexpr std::string_view HEADER_SIGNATURE = "X-FS-Signature";
constexpr std::string_view HEADER_TTL = "X-FS-TTL";

constexpr std::string_view ENDPOINT_FILE = "file";
constexpr std::string_view ENDPOINT_FILE_INDIVIDUAL = "file/{}";
constexpr std::string_view ENDPOINT_EXTEND = "file/{}/extend";

constexpr std::string_view LEGACY_ENDPOINT_FILE_INDIVIDUAL = "files/{}";

std::optional<DownloadInfo> parse_download_url(std::string_view url) {
    // Expected format: {scheme}://{host}/file/{file_id}(?:#p={customPubkey})(?:d)
    // Examples:
    //   https://example.com/file/abc123
    //   https://example.com/file/abc123#p=da21e1d886c6fbaea313f75298bd64aab03a97ce985b46bb2dad9f2089c8ee59
    //   https://example.com/file/abc123#d
    //   https://example.com/file/abc123#p=abc123&d
    DownloadInfo info{};

    auto match = backends::match_endpoint(ENDPOINT_FILE_INDIVIDUAL, url);

    if (!match || match->base.empty() || match->captures.size() != 1) {
        // Need to fallback to checking the legacy endpoint because some clients seem to still be
        // generating download urls with it
        match = backends::match_endpoint(LEGACY_ENDPOINT_FILE_INDIVIDUAL, url);

        if (!match || match->base.empty() || match->captures.size() != 1)
            return std::nullopt;
    }

    info.file_id = match->captures[0];

    auto scheme_end = match->base.find("://");
    if (scheme_end == std::string_view::npos)
        return std::nullopt;

    info.scheme = std::string{match->base.substr(0, scheme_end)};

    // `to_request` builds a `ServerDestination` from host and port SEPARATELY, so a port left
    // inside the host reaches the network layer as a valid-looking hostname pointing nowhere.
    auto authority = match->base.substr(scheme_end + 3);
    auto port_sep = authority.rfind(':');

    if (port_sep != std::string_view::npos) {
        // An IPv6 literal is full of colons, so the last one separates a port only when a number
        // follows it. `parse_int` must consume the whole string, which is what lets `[::1]` keep
        // its colons while `[::1]:8000` gives up just the port.
        uint16_t parsed_port = 0;
        if (quic::parse_int(authority.substr(port_sep + 1), parsed_port) && parsed_port != 0) {
            info.port = parsed_port;
            authority = authority.substr(0, port_sep);
        }
    }

    info.host = std::string{authority};
    info.wants_stream_decryption = false;

    // Parse fragments if present (p=... and/or d)
    auto fragment_pos = url.find('#');
    if (fragment_pos == std::string_view::npos)
        return info;

    auto fragments = url.substr(fragment_pos + 1);

    for (auto fragment : split(fragments, "&", true)) {
        if (fragment == backends::FRAGMENT_STREAM_ENCRYPTION)
            info.wants_stream_decryption = true;
        else if (
                fragment.starts_with(fmt::format("{}=", backends::FRAGMENT_PUBKEY)) &&
                fragment.size() == 66 &&  // 'p=' + pubkey
                oxenc::is_hex(fragment.substr(2)) &&
                fragment.substr(2) != file_server::DEFAULT_CONFIG.pubkey_hex)
            info.custom_pubkey_hex = fragment.substr(2);
        // else ignore (unknown or invalid fragment)
    }

    return info;
}

// The port a url does not need to state, because the scheme already implies it.
static uint16_t default_port_for_scheme(std::string_view scheme) {
    return (scheme == "https" ? 443 : 80);
}

std::string generate_download_url(std::string_view file_id, const config::FileServer& config) {
    const auto has_custom_pubkey = (config.pubkey_hex != file_server::DEFAULT_CONFIG.pubkey_hex);

    // Omitted when the scheme already implies it, so urls for the default file server are
    // byte-identical to those any other client produces for it.
    const auto port_suffix =
            (config.port == default_port_for_scheme(config.scheme)
                     ? ""
                     : fmt::format(":{}", config.port));

    auto buf = fmt::format(
            "{}://{}{}/{}",
            config.scheme,
            config.host,
            port_suffix,
            fmt::format(file_server::ENDPOINT_FILE_INDIVIDUAL, file_id));

    if (config.use_stream_encryption || has_custom_pubkey) {
        buf += "#";

        if (has_custom_pubkey)
            buf += fmt::format("{}={}", backends::FRAGMENT_PUBKEY, config.pubkey_hex);

        if (config.use_stream_encryption) {
            buf += (has_custom_pubkey ? "&" : "");
            buf += backends::FRAGMENT_STREAM_ENCRYPTION;
        }
    }

    return buf;
}

std::optional<std::chrono::sys_seconds> parse_http_date(std::string_view date_str) {

    auto t = std::make_optional<std::chrono::sys_seconds>();
    std::istringstream ss{std::string{date_str}};
    ss.imbue(std::locale::classic());
    if (!(ss >> chrono_for_parsing::parse("%a, %d %b %Y %T %Z", *t) >> std::ws) || !ss.eof())
        t.reset();
    return t;
}

Request to_request(
        const std::string& upload_id,
        const config::FileServer& config,
        UploadRequest upload_request) {
    std::vector<unsigned char> all_data;

    while (true) {
        if (upload_request.is_cancelled())
            throw std::runtime_error{"Request cancelled"};

        auto chunk = upload_request.next_data();

        if (chunk.empty())
            break;

        // Safety check to prevent runaway memory usage
        if (all_data.size() + chunk.size() > config.max_file_size)
            throw std::runtime_error{"File too large"};

        all_data.insert(all_data.end(), chunk.begin(), chunk.end());
    }

    if (all_data.empty())
        throw std::runtime_error{"No data to upload"};

    std::vector<std::pair<std::string, std::string>> headers;
    headers.emplace_back(HEADER_CONTENT_TYPE, "application/octet-stream");

    if (upload_request.file_name) {
        headers.emplace_back(
                HEADER_CONTENT_DISPOSITION,
                fmt::format("attachment; filename=\"{}\"", *upload_request.file_name));
    } else {
        headers.emplace_back(HEADER_CONTENT_DISPOSITION, "attachment");
    }

    if (upload_request.ttl)
        headers.emplace_back(HEADER_TTL, "{}"_format(upload_request.ttl->count()));

    return Request{
            upload_id,
            ServerDestination{
                    config.scheme,
                    config.host,
                    compute_x25519_pubkey(
                            to_span<unsigned char>(oxenc::from_hex(config.pubkey_hex))),
                    config.port,
                    std::move(headers),
                    "POST"},
            std::string{file_server::ENDPOINT_FILE},
            std::move(all_data),
            RequestCategory::file,
            upload_request.request_timeout,
            upload_request.overall_timeout};
}

Request to_request(
        const std::string& download_id,
        const config::FileServer& config,
        DownloadRequest download_request) {
    auto download_info = file_server::parse_download_url(download_request.download_url);

    if (!download_info)
        throw invalid_url_exception{"Invalid download url"};

    std::string file_id = download_info->file_id;
    std::string scheme = download_info->scheme;
    std::string host = download_info->host;
    std::string pubkey_hex =
            (download_info->custom_pubkey_hex.has_value() ? *download_info->custom_pubkey_hex
                                                          : config.pubkey_hex);

    // The url's port, not the local config's: the file lives on the SENDER's file server, which the
    // recipient may never have heard of.
    uint16_t port = download_info->port.value_or(config.port);

    return Request{
            download_id,
            ServerDestination{
                    std::move(scheme),
                    std::move(host),
                    compute_x25519_pubkey(to_span<unsigned char>(oxenc::from_hex(pubkey_hex))),
                    port,
                    std::nullopt,
                    "GET"},
            fmt::format("{}/{}", file_server::ENDPOINT_FILE, file_id),
            std::nullopt,
            RequestCategory::file,
            download_request.request_timeout,
            download_request.overall_timeout};
}

file_metadata parse_upload_response(const std::string& body, size_t upload_size) {
    auto json = nlohmann::json::parse(body);

    if (!json.contains("id") || !json["id"].is_string())
        throw std::runtime_error{"Upload response missing required 'id' field"};

    file_metadata metadata{};
    metadata.id = json["id"].get<std::string>();
    metadata.size = json.value("size", 0);

    if (metadata.size == 0)
        metadata.size = upload_size;

    if (json.contains("uploaded") && json["uploaded"].is_number()) {
        auto uploaded = json["uploaded"].get<int64_t>();
        metadata.uploaded = std::chrono::sys_seconds{std::chrono::seconds(uploaded)};
    }

    if (json.contains("expires") && json["expires"].is_number()) {
        auto expiry = json["expires"].get<int64_t>();
        metadata.expiry = std::chrono::sys_seconds{std::chrono::seconds(expiry)};
    }

    return metadata;
}

std::pair<file_metadata, std::vector<unsigned char>> parse_download_response(
        std::string_view download_url,
        const std::vector<std::pair<std::string, std::string>>& headers,
        const std::string& body) {
    auto download_info = parse_download_url(download_url);
    if (!download_info)
        throw invalid_url_exception{"Could not retrieve file_id"};

    file_metadata metadata{};
    metadata.id = download_info->file_id;

    for (const auto& [key, value] : headers) {
        if (key == "content-length") {
            int64_t size;

            if (quic::parse_int(value, size))
                metadata.size = std::stoll(value);
        } else if (key == "expires") {
            if (auto expiry_time = parse_http_date(value))
                metadata.expiry = *expiry_time;
        }
    }

    std::vector<unsigned char> data(body.begin(), body.end());

    if (metadata.size == 0)
        metadata.size = data.size();

    return {std::move(metadata), std::move(data)};
}

Request extend_ttl(
        std::string_view file_id,
        std::chrono::seconds ttl,
        const config::FileServer& config,
        std::chrono::milliseconds request_timeout,
        std::optional<std::chrono::milliseconds> overall_timeout) {
    auto headers = std::vector<std::pair<std::string, std::string>>{};
    headers.emplace_back(HEADER_TTL, "{}"_format(ttl.count()));

    return Request{
            random::unique_id("ETLL"),
            ServerDestination{
                    config.scheme,
                    config.host,
                    compute_x25519_pubkey(
                            to_span<unsigned char>(oxenc::from_hex(config.pubkey_hex))),
                    config.port,
                    std::move(headers),
                    "POST"},
            fmt::format(ENDPOINT_EXTEND, file_id),
            std::nullopt,
            RequestCategory::file_small,
            request_timeout,
            overall_timeout};
}

Request get_client_version(
        Platform platform,
        network::ed25519_seckey seckey,
        std::chrono::milliseconds request_timeout,
        std::optional<std::chrono::milliseconds> overall_timeout) {
    std::string endpoint;

    switch (platform) {
        case Platform::android: endpoint = "/session_version?platform=android"; break;
        case Platform::desktop: endpoint = "/session_version?platform=desktop"; break;
        case Platform::ios: endpoint = "/session_version?platform=ios"; break;
    }

    // Generate the auth signature
    auto blinded_keys = blind_version_key_pair(to_span(seckey.view()));
    auto timestamp = epoch_seconds(std::chrono::system_clock::now());
    auto signature = blind_version_sign(to_span(seckey.view()), platform, timestamp);
    auto pubkey = compute_x25519_pubkey(
            to_span<unsigned char>(oxenc::from_hex(DEFAULT_CONFIG.pubkey_hex)));
    std::string blinded_pk_hex;
    blinded_pk_hex.reserve(66);
    blinded_pk_hex += "07";
    oxenc::to_hex(
            blinded_keys.first.begin(),
            blinded_keys.first.end(),
            std::back_inserter(blinded_pk_hex));

    auto headers = std::vector<std::pair<std::string, std::string>>{};
    headers.emplace_back(HEADER_PUBKEY, blinded_pk_hex);
    headers.emplace_back(HEADER_TIMESTAMP, "{}"_format(timestamp));
    headers.emplace_back(HEADER_SIGNATURE, oxenc::to_base64(signature.begin(), signature.end()));

    return Request{
            random::unique_id("GCV"),
            ServerDestination{
                    DEFAULT_CONFIG.scheme,
                    DEFAULT_CONFIG.host,
                    pubkey,
                    DEFAULT_CONFIG.port,
                    headers,
                    "GET"},
            std::move(endpoint),
            std::nullopt,
            RequestCategory::file_small,
            request_timeout,
            overall_timeout};
}

}  // namespace session::network::file_server

extern "C" {

using namespace session;
using namespace session::network;

LIBSESSION_C_API bool session_file_server_parse_download_url(
        const char* url, file_server_parsed_download_url* out) {
    auto info = file_server::parse_download_url(url);
    if (!info)
        return false;

    auto copy = [](auto& dest, const std::string& src) {
        auto len = std::min(src.size(), sizeof(dest) - 1);
        std::memcpy(dest, src.c_str(), len);
        dest[len] = '\0';
    };

    copy(out->scheme, info->scheme);
    copy(out->host, info->host);
    out->port = info->port.value_or(0);  // 0 means the scheme's default
    copy(out->file_id, info->file_id);
    copy(out->custom_pubkey_hex, info->custom_pubkey_hex.value_or(""));
    out->wants_stream_decryption = info->wants_stream_decryption;
    return true;
}

LIBSESSION_C_API bool session_file_server_generate_download_url(
        const char* file_id,
        const char* scheme,
        const char* host,
        uint16_t port,
        const char* pubkey_hex,
        bool use_stream_encryption,
        char* out_url,
        size_t out_url_len) {
    if (!file_id)
        return false;

    network::config::FileServer config = file_server::DEFAULT_CONFIG;
    if (scheme)
        config.scheme = scheme;
    if (host)
        config.host = host;
    if (port != 0)
        config.port = port;
    if (pubkey_hex)
        config.pubkey_hex = pubkey_hex;
    config.use_stream_encryption = use_stream_encryption;

    auto result = file_server::generate_download_url(file_id, config);
    if (result.size() >= out_url_len)
        return false;

    std::memcpy(out_url, result.c_str(), result.size() + 1);
    return true;
}

LIBSESSION_C_API session_request_params* session_file_server_get_client_version(
        CLIENT_PLATFORM platform,
        const unsigned char* ed25519_secret, /* 64 bytes */
        int64_t request_timeout_ms,
        int64_t overall_timeout_ms) {
    try {
        auto req = file_server::get_client_version(
                static_cast<Platform>(platform),
                network::ed25519_seckey::from_bytes({ed25519_secret, 64}),
                std::chrono::milliseconds{request_timeout_ms},
                (overall_timeout_ms > 0
                         ? std::optional{std::chrono::milliseconds{overall_timeout_ms}}
                         : std::nullopt));

        return session::network::detail::convert_cpp_request_to_c(req);
    } catch (...) {
        return nullptr;
    }
}

}  // extern "C"
