#pragma once

#include <cstddef>
#include <filesystem>
#include <fstream>
#include <functional>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace session::attachment {
class PushEncryptor;
}

/// A cache of files we downloaded, on disk, encrypted under one key of our own.
///
/// Re-encrypted rather than kept as the file server gave them to us, because the key that opened a
/// download belongs to something that goes away: an attachment's key lives in the message, a
/// profile picture's in the Contacts config, and a deleted message or a changed picture would leave
/// us holding a file we can no longer read.  A key we own outlives both.
///
/// Encrypted rather than kept as plaintext because the disk is not a trusted place: it ends up in
/// backups, in disk images, and in whoever's hands the machine does.  That is also why the padding
/// is kept -- see `attachment::Encryptor`'s key-taking constructor.
///
/// The two halves are kept differently, because only one of them expires.  A cached picture is just
/// a file: what still references it is already recorded in `accounts.profile_pic_url`, and a second
/// record of it would be a second thing to keep in step.  A cached attachment additionally has a
/// row in `attachment_cache`, because eviction has to answer "what is the total, and what was used
/// longest ago" without stat-ing the whole directory to find out.
///
/// That row is an index over the file rather than a second copy of the truth, and either can be
/// missing the other after a crash: a sweep reconciles both directions.
namespace session::client::cache {

/// The subdirectory a kind of download lives in.  Separate so that a sweep of one cannot consider
/// the other's files unreferenced, which it would, since neither knows the other's urls.
inline constexpr std::string_view PROFILE_DIR = "profile";
inline constexpr std::string_view ATTACHMENT_DIR = "attachments";

/// The name `url`'s cached file takes, and where that file lives beneath `dir`.
///
/// Named for a keyed hash of the url with any query string and fragment removed.  Those are not
/// part of which file this is: the fragment carries what is needed to *reach* and unpack the bytes
/// -- the server's key, connection details, decompression hints -- while the bytes at the base url
/// are the bytes.  Two references differing only there name the same file, and hashing the whole
/// thing would cache it twice.
///
/// Hashed rather than escaped because a url is not a filename: it is long, it contains separators,
/// and its length is unbounded.  A fixed-width hex name is none of those things.
///
/// **Keyed**, and that is not optional.  An unkeyed name is a function of public information, so
/// the directory answers "did this account download *this* url" to anyone who can read it and
/// guess a url -- which encryption does nothing about, the question being settled by the filename
/// before any file is opened.  `key` is `client:cache_key`, the same secret the files are encrypted
/// under, kept apart from that use by the personalisation rather than by luck.
std::string name_for(std::span<const std::byte, 32> key, std::string_view url);

std::filesystem::path path_for(
        const std::filesystem::path& dir,
        std::string_view kind,
        std::span<const std::byte, 32> key,
        std::string_view url);

/// Reads and decrypts a cached file, or nullopt if it is not there.
///
/// Nullopt for an unreadable or corrupted file too, rather than throwing: a cache that cannot
/// answer is a cache miss, and the caller's next move -- fetch it again -- is the same either way.
/// The unreadable file is removed, since nothing else would ever remove it.
std::optional<std::vector<std::byte>> read(
        const std::filesystem::path& file, std::span<const std::byte, 32> key);

/// `read`, a piece at a time: each decrypted piece is handed to `out` as it comes, so a file too
/// large to hold whole never has to be.  False, having removed it, for a file that turns out to be
/// unreadable -- in which case `out` may already have been handed part of it, and whatever it did
/// with that is its to undo.
bool read_into(
        const std::filesystem::path& file,
        std::span<const std::byte, 32> key,
        const std::function<void(std::span<const std::byte>)>& out);

/// Encrypts `data` and writes it to `file`, creating the directory if needed.
///
/// Written to a temporary name in the same directory and renamed into place, so a crash or a
/// concurrent read never sees a half-written file: the rename is atomic and the name only ever
/// exists complete.  The temporary carries a suffix a sweep knows to leave alone.
void write(
        const std::filesystem::path& file,
        std::span<const std::byte, 32> key,
        std::span<const std::byte> data);

/// `write`, for bytes that arrive in pieces: each is encrypted and written as it comes, so a file
/// too large to hold whole never has to be.
///
/// Made once the padding is known, which the encryption needs before the first byte since it pads
/// at the front: for a download re-encrypted into the cache, the padding the download carried
/// (`attachment::Decryptor::padding()`), and otherwise `attachment::encrypted_padding()` of a size
/// that is known.  The length is never needed.
///
/// Constructing it opens the file, so a cache that cannot be written to throws there.  Nothing
/// appears under `file` until `commit`; a Writer destroyed without one, whether abandoned or
/// because something threw, removes what it had written, so a failed download leaves nothing.
class Writer {
  public:
    Writer(std::filesystem::path file, std::span<const std::byte, 32> key, size_t padding);
    ~Writer();

    Writer(const Writer&) = delete;
    Writer& operator=(const Writer&) = delete;

    /// Throws if the disk write fails.
    void write(std::span<const std::byte> data);

    /// Finishes the file and renames it into place.  Throws if finishing the file fails.
    void commit();

  private:
    std::filesystem::path _file, _tmp;
    std::ofstream _out;
    std::unique_ptr<attachment::PushEncryptor> _enc;
    bool _committed = false;

    // Closes and removes the temporary: what an unfinished write leaves.
    void _discard() noexcept;
};

/// The suffix an in-progress write carries.  A sweep must skip these: it decides what to delete by
/// what is *not* referenced, and a download that has not finished is not referenced yet.
inline constexpr std::string_view PARTIAL_SUFFIX = ".part";

/// The names of the finished files in `dir/kind`, in no particular order.
///
/// Filesystem only, reading nothing else, so this half of a sweep can run off the event loop --
/// which is the point of it being its own function.  Walking a directory of many thousands of files
/// is the slow part; deciding what to do about them is a handful of queries.
///
/// In-progress writes are left out, since a download that has not finished is not yet referenced by
/// anything and a sweep would take it for garbage.
std::vector<std::string> list(const std::filesystem::path& dir, std::string_view kind);

/// Unlinks a file `list` named.  True if it went, false if it was already gone -- which is not an
/// error: between listing a name and acting on it, eviction may have removed it anyway.
bool remove(const std::filesystem::path& dir, std::string_view kind, std::string_view name);

}  // namespace session::client::cache
