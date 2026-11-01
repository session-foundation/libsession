#include "../../src/client/download_cache.hpp"

#include <fstream>
#include <session/random.hpp>

#include "common.hpp"

namespace cache = session::client::cache;

namespace {

// A temporary directory that removes itself, so a failing assertion cannot leave one behind.
struct TempDir {
    std::filesystem::path path{
            std::filesystem::temp_directory_path() /
            fmt::format("{}", session::random::unique_id("test_cache", 8))};

    TempDir() { std::filesystem::create_directories(path); }
    ~TempDir() {
        std::error_code ec;
        std::filesystem::remove_all(path, ec);
    }
};

b32 a_key() {
    b32 k;
    session::random::fill(k);
    return k;
}

}  // namespace

TEST_CASE("Cache: a url names one file, whatever is hung off it", "[client][cache]") {
    TempDir dir;
    auto key = a_key();

    auto base = cache::path_for(dir.path, cache::PROFILE_DIR, key, "http://fs.example/file/1234");
    auto fragment = cache::path_for(
            dir.path, cache::PROFILE_DIR, key, "http://fs.example/file/1234#pubkey=abcdef");
    auto query =
            cache::path_for(dir.path, cache::PROFILE_DIR, key, "http://fs.example/file/1234?v=2");

    // The bytes at the base url are the bytes; a fragment says how to reach and unpack them, and a
    // query string is not part of which file this is.
    CHECK(base == fragment);
    CHECK(base == query);

    // A different file is a different entry.
    CHECK(base !=
          cache::path_for(dir.path, cache::PROFILE_DIR, key, "http://fs.example/file/5678"));

    // And the two kinds do not share a directory, so a sweep of one cannot see the other's files.
    CHECK(base !=
          cache::path_for(dir.path, cache::ATTACHMENT_DIR, key, "http://fs.example/file/1234"));

    // The name is a hash, not the url: usable as a filename whatever the url looked like.
    CHECK(base.filename().string().size() == 64);
    CHECK(base.filename().string().find('/') == std::string::npos);
}

TEST_CASE("Cache: the name is keyed, so a directory is not a list of urls", "[client][cache]") {
    // The point of the key.  Without one, a name is a function of public information, so anyone who
    // can read the directory and guess a url learns whether this account downloaded it -- a
    // question the encryption never gets asked, because the filename settles it before any file is
    // opened.  Two accounts caching the same url must therefore agree on nothing.
    constexpr auto url = "http://fs.example/file/1234";

    auto mine = a_key(), theirs = a_key();
    CHECK(cache::name_for(mine, url) != cache::name_for(theirs, url));

    // Same key, same url, same name -- otherwise nothing would ever be found again.
    CHECK(cache::name_for(mine, url) == cache::name_for(mine, url));
}

TEST_CASE("Cache: what goes in comes back out", "[client][cache]") {
    TempDir dir;
    auto key = a_key();
    auto file = cache::path_for(dir.path, cache::PROFILE_DIR, key, "http://fs.example/file/1");

    CHECK_FALSE(cache::read(file, key).has_value());

    std::vector<std::byte> data(5000);
    session::random::fill(data);
    cache::write(file, key, data);

    REQUIRE(std::filesystem::exists(file));
    auto got = cache::read(file, key);
    REQUIRE(got);
    CHECK(*got == data);

    // On disk it is not the plaintext: the file is bigger than what went in (header, macs, padding)
    // and does not contain it.
    auto on_disk = std::filesystem::file_size(file);
    CHECK(on_disk > data.size());

    // Another key does not open it, and the unreadable entry is dropped rather than left to fail
    // forever.
    auto other = a_key();
    CHECK_FALSE(cache::read(file, other).has_value());
    CHECK_FALSE(std::filesystem::exists(file));
}

TEST_CASE("Cache: a file can be written as it arrives", "[client][cache]") {
    TempDir dir;
    auto key = a_key();
    auto file = cache::path_for(dir.path, cache::ATTACHMENT_DIR, key, "http://fs.example/file/3");

    // Several chunks' worth, arriving in pieces that line up with nothing: the encryption works a
    // chunk at a time, and must neither run dry partway through one nor hold more than it needs.
    auto size = GENERATE(0, 1, 32768, 32769, 200'000);
    auto piece = GENERATE(1, 7, 4096, 40'000);
    std::vector<std::byte> data(size);
    session::random::fill(data);

    {
        cache::Writer w{file, key, session::attachment::encrypted_padding(data.size())};
        for (std::span rest{data}; !rest.empty();) {
            auto n = std::min<size_t>(piece, rest.size());
            w.write(rest.first(n));
            rest = rest.subspan(n);
        }
        // Nothing to be found until it is finished, so a reader either misses or gets all of it.
        CHECK_FALSE(std::filesystem::exists(file));
        w.commit();
    }

    auto got = cache::read(file, key);
    REQUIRE(got);
    CHECK(*got == data);
    CHECK(cache::list(dir.path, cache::ATTACHMENT_DIR).size() == 1);
}

TEST_CASE("Cache: a write that does not finish leaves nothing", "[client][cache]") {
    TempDir dir;
    auto key = a_key();
    auto file = cache::path_for(dir.path, cache::ATTACHMENT_DIR, key, "http://fs.example/file/4");
    std::vector<std::byte> data(100'000);
    session::random::fill(data);

    auto leftovers = [&] {
        size_t n = 0;
        for (const auto& e : std::filesystem::directory_iterator{file.parent_path()}) {
            (void)e;
            n++;
        }
        return n;
    };

    // Abandoned partway, as a failed download is.
    {
        cache::Writer w{file, key, session::attachment::encrypted_padding(data.size())};
        w.write(std::span{data}.first(50'000));
    }
    CHECK(leftovers() == 0);
    CHECK_FALSE(cache::read(file, key));

    // One that cannot even start throws there, before anything is fetched on its account.
    auto blocked = dir.path / "not-a-directory";
    std::ofstream{blocked} << "in the way";
    CHECK_THROWS(cache::Writer{blocked / "file", key, 1});
}

TEST_CASE("Cache: a corrupted entry is a miss, not a throw", "[client][cache]") {
    TempDir dir;
    auto key = a_key();
    auto file = cache::path_for(dir.path, cache::ATTACHMENT_DIR, key, "http://fs.example/file/2");

    std::vector<std::byte> data(100);
    session::random::fill(data);
    cache::write(file, key, data);

    {
        std::ofstream out{file, std::ios::binary | std::ios::app};
        out << "rubbish";
    }

    CHECK_FALSE(cache::read(file, key).has_value());
    CHECK_FALSE(std::filesystem::exists(file));
}

TEST_CASE("Cache: listing offers up what a sweep may consider", "[client][cache]") {
    TempDir dir;
    auto key = a_key();

    std::vector<std::byte> data(64);
    session::random::fill(data);

    std::string kept = "http://fs.example/file/keep";
    std::string dropped = "http://fs.example/file/drop";
    cache::write(cache::path_for(dir.path, cache::PROFILE_DIR, key, kept), key, data);
    cache::write(cache::path_for(dir.path, cache::PROFILE_DIR, key, dropped), key, data);

    // A download still running: no url references it yet, and unlinking it would fail the fetch for
    // a reason nothing could explain.
    auto partial =
            cache::path_for(dir.path, cache::PROFILE_DIR, key, "http://fs.example/file/busy");
    partial += "-abcdefgh";
    partial += std::string{cache::PARTIAL_SUFFIX};
    {
        std::ofstream out{partial, std::ios::binary};
        out << "half a file";
    }

    auto listed = cache::list(dir.path, cache::PROFILE_DIR);
    std::set<std::string> names{listed.begin(), listed.end()};

    // Two finished files and not the third: what is offered up is only what a sweep may act on.
    CHECK(names.size() == 2);
    CHECK(names.contains(cache::name_for(key, kept)));
    CHECK_FALSE(names.contains(partial.filename().string()));

    // The referencing url carries a fragment, as a stored one may, and still names the same file --
    // which is what lets a caller decide by url what to keep by name.
    CHECK(names.contains(cache::name_for(key, kept + "#pubkey=aa")));

    CHECK(cache::remove(dir.path, cache::PROFILE_DIR, cache::name_for(key, dropped)));
    CHECK_FALSE(
            std::filesystem::exists(cache::path_for(dir.path, cache::PROFILE_DIR, key, dropped)));
    CHECK(std::filesystem::exists(cache::path_for(dir.path, cache::PROFILE_DIR, key, kept)));
    CHECK(std::filesystem::exists(partial));

    // Removing what is already gone is the ordinary outcome of two sweeps racing, not an error.
    CHECK_FALSE(cache::remove(dir.path, cache::PROFILE_DIR, cache::name_for(key, dropped)));

    // A directory that was never created lists as empty rather than throwing: a client that has
    // cached no attachments has no attachments directory.
    CHECK(cache::list(dir.path, cache::ATTACHMENT_DIR).empty());
}
