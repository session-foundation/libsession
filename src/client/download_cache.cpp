#include "download_cache.hpp"

#include <oxenc/hex.h>

#include <cstring>
#include <fstream>
#include <oxen/log.hpp>
#include <session/attachments.hpp>
#include <session/format.hpp>
#include <session/hash.hpp>
#include <session/random.hpp>

namespace session::client::cache {

namespace log = oxen::log;
static auto cat = log::Cat("client");

namespace {

    std::string_view base_url(std::string_view url) {
        if (auto q = url.find_first_of("?#"); q != std::string_view::npos)
            url = url.substr(0, q);
        return url;
    }

}  // namespace

std::string name_for(std::span<const std::byte, 32> key, std::string_view url) {
    // Keyed, so the name is a MAC rather than a digest.  Unkeyed, the directory is an oracle: hash
    // a url you are curious about, see whether that file is there, and you know this account
    // downloaded it -- which the encryption does nothing about, since the question is answered by
    // the name alone.  With a key nobody else has, the listing says only how many files there are.
    //
    // Personalised because the same key encrypts the files: one key, two uses, kept apart by the
    // personalisation rather than by hoping the primitives never meet.
    constexpr auto PERS_CACHE_NAME = "SessionCacheName"_b2b_pers;
    auto h = hash::blake2b_key_pers<32>(key, PERS_CACHE_NAME, base_url(url));
    return oxenc::to_hex(h.begin(), h.end());
}

std::filesystem::path path_for(
        const std::filesystem::path& dir,
        std::string_view kind,
        std::span<const std::byte, 32> key,
        std::string_view url) {
    return dir / kind / name_for(key, url);
}

std::optional<std::vector<std::byte>> read(
        const std::filesystem::path& file, std::span<const std::byte, 32> key) {
    std::error_code ec;
    if (!std::filesystem::exists(file, ec))
        return std::nullopt;

    try {
        std::ifstream in{file, std::ios::binary | std::ios::ate};
        in.exceptions(std::ios::failbit | std::ios::badbit);

        std::vector<std::byte> encrypted(static_cast<size_t>(in.tellg()));
        in.seekg(0);
        in.read(reinterpret_cast<char*>(encrypted.data()),
                static_cast<std::streamsize>(encrypted.size()));

        return attachment::decrypt(encrypted, key);
    } catch (const std::exception& e) {
        // A cache that cannot answer is a cache miss; the caller fetches instead.  Removed because
        // nothing else ever would: it is not referenced by anything that could notice it is bad.
        log::warning(cat, "Discarding unreadable cache entry {}: {}", file.string(), e.what());
        std::filesystem::remove(file, ec);
        return std::nullopt;
    }
}

bool read_into(
        const std::filesystem::path& file,
        std::span<const std::byte, 32> key,
        const std::function<void(std::span<const std::byte>)>& out) {
    std::error_code ec;
    if (!std::filesystem::exists(file, ec))
        return false;

    try {
        std::ifstream in;
        in.exceptions(std::ios::badbit);
        in.open(file, std::ios::binary);

        attachment::Decryptor d{key, out};
        std::vector<std::byte> chunk(attachment::ENCRYPTED_CHUNK_TOTAL);
        while (in) {
            in.read(reinterpret_cast<char*>(chunk.data()),
                    static_cast<std::streamsize>(chunk.size()));
            auto got = static_cast<size_t>(in.gcount());
            if (got > 0 && !d.update(std::span{chunk}.first(got)))
                throw std::runtime_error{"decryption failed"};
        }
        if (!d.finalize())
            throw std::runtime_error{"entry ends partway"};
        return true;
    } catch (const std::exception& e) {
        // As for `read`.  The caller may already have been handed some of it, which is theirs to
        // discard: a failure here is a failure of the whole read.
        log::warning(cat, "Discarding unreadable cache entry {}: {}", file.string(), e.what());
        std::filesystem::remove(file, ec);
        return false;
    }
}

void write(
        const std::filesystem::path& file,
        std::span<const std::byte, 32> key,
        std::span<const std::byte> data) {
    Writer w{file, key, attachment::encrypted_padding(data.size())};
    w.write(data);
    w.commit();
}

Writer::Writer(std::filesystem::path file, std::span<const std::byte, 32> key, size_t padding) :
        _file{std::move(file)} {
    std::filesystem::create_directories(_file.parent_path());

    // Unique, so two writes of the same url cannot land on one temporary and interleave.
    _tmp = _file;
    _tmp += "{}{}"_format(random::unique_id("-", 8), PARTIAL_SUFFIX);

    _out.exceptions(std::ios::failbit | std::ios::badbit);
    _out.open(_tmp, std::ios::binary | std::ios::trunc);

    // The encryptor writes the header and padding as it is made.  A constructor that throws gets
    // no destructor, so the file just opened has to be removed here if that fails.
    try {
        _enc = std::make_unique<attachment::PushEncryptor>(
                key, padding, [this](std::span<const std::byte> encrypted) {
                    _out.write(
                            reinterpret_cast<const char*>(encrypted.data()),
                            static_cast<std::streamsize>(encrypted.size()));
                });
    } catch (...) {
        _discard();
        throw;
    }
}

Writer::~Writer() {
    if (!_committed)
        _discard();
}

void Writer::write(std::span<const std::byte> data) {
    _enc->update(data);
}

void Writer::commit() {
    _enc->finalize();
    _out.close();

    // Atomic: the finished name never exists holding a partial file, so a reader either misses or
    // gets the whole thing.
    std::filesystem::rename(_tmp, _file);
    _committed = true;
}

void Writer::_discard() noexcept {
    try {
        _out.close();
    } catch (...) {
    }
    std::error_code ec;
    std::filesystem::remove(_tmp, ec);
}

std::vector<std::string> list(const std::filesystem::path& dir, std::string_view kind) {
    std::vector<std::string> names;

    std::error_code ec;
    for (const auto& entry : std::filesystem::directory_iterator{dir / kind, ec}) {
        auto name = entry.path().filename().string();
        // A download still running is not garbage, it is unfinished, and unlinking it mid-write
        // would make the fetch fail for a reason nothing could explain.
        if (name.ends_with(PARTIAL_SUFFIX))
            continue;
        names.push_back(std::move(name));
    }
    return names;
}

bool remove(const std::filesystem::path& dir, std::string_view kind, std::string_view name) {
    std::error_code ec;
    return std::filesystem::remove(dir / kind / name, ec);
}

}  // namespace session::client::cache
