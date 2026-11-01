#pragma once

#include <filesystem>
#include <optional>
#include <session/clock.hpp>
#include <session/expected.hpp>
#include <string>
#include <vector>

namespace session::client {

/// Longest ThumbHash we will store.
///
/// The format's own ceiling: a 7x7 luminance DCT, 3x3 for each of P and Q, and 5x5 alpha, which
/// comes to 25 bytes.  A bound on what a remote peer can put in the database rather than a parse
/// -- the bytes stay opaque here, and nothing checks that they decode.
constexpr size_t MAX_THUMBHASH_SIZE = 25;

/// A file to attach to an outgoing message.  Attaching costs nothing: the file is read, encrypted
/// and uploaded when the message is sent, not when it is attached, so a caller can hold these
/// against a draft for as long as the user takes to write it.
struct OutgoingAttachment {
    /// The file to send.  Read at send time, so it must still be there and unchanged by then.
    std::filesystem::path path;

    /// MIME type to advertise.  Recipients use it to decide how to display the attachment; when
    /// unset it is inferred from the filename's extension.
    std::optional<std::string> content_type;

    /// Name to advertise, defaulting to `path`'s filename.  Worth setting explicitly when the
    /// local file is a temporary whose name means nothing to the recipient.
    std::optional<std::string> filename;

    /// Marks this as a recorded voice message rather than an ordinary audio file, which clients
    /// present differently.
    bool voice_message = false;

    /// Pixel dimensions, for visual media.  Recipients use them to lay out a placeholder before
    /// the file itself has been fetched, so supplying them avoids the layout jumping.
    ///
    /// TODO: these are the caller's to supply because libsession cannot read them -- deriving them
    /// means either an image library or hand-written header parsing of untrusted files.  Worth
    /// revisiting if libsession takes on an image dependency for other reasons (thumbnailing, say),
    /// at which point every client stops needing its own.
    std::optional<uint32_t> width;
    std::optional<uint32_t> height;

    /// ThumbHash of the image, for a recipient to draw in the attachment's place until the file
    /// itself arrives.  Advisory and unvalidated: libsession carries the bytes and never looks
    /// inside them.
    ///
    /// The caller's to supply for the same reason as `width`/`height` above: encoding one needs
    /// the pixels, which means decoding and scaling the image, and that is the dependency the
    /// comment beside those two declines to take on.
    std::optional<std::vector<std::byte>> thumbhash;
};

/// An attachment on a stored message, in either direction, as reported on `Message::attachments`.
///
/// The descriptive fields are the same ones `OutgoingAttachment` supplies, and on an incoming
/// attachment they are the sender's claims: nothing here has been checked against the file, which
/// has usually not been fetched at all.  In particular `content_type` and `filename` are chosen by
/// whoever sent it, so treat them as display hints rather than as facts about the bytes.
/// What a conversation fetches without being asked.
///
/// `image_attachments` rather than "images" because a display picture is an image too and is not
/// governed by this: it is always fetched, whatever this says.  This is only ever about files sent
/// with a message.
enum class AutoDownload : int {
    none = 0,               ///< Nothing; every attachment waits to be asked for.
    image_attachments = 1,  ///< Attachments whose content type is an image.
    all = 2,                ///< Every attachment.
};

/// How an attachment transfer is going.
///
/// Reported two ways, for the two kinds of transfer: handed directly to whoever called
/// `attachment_data` or `save_attachment`, and — for a download nobody asked for — broadcast
/// through `callbacks::attachment_progress`, since a background fetch has no caller to hand
/// anything to.
struct AttachmentProgress {
    int64_t message_id;
    size_t index;

    /// The request this reports on, as `attachment_data` and `save_attachment` return it, for
    /// `Client::cancel_attachment_transfer`.  Several requests sharing one download each have their
    /// own, and an auto-download has one too, which reaches the application only through here.
    uint64_t token = 0;

    /// Encrypted bytes so far, and how many are expected.  Encrypted rather than the file's own
    /// size because that is what is actually being moved and therefore what a proportion should be
    /// computed from; the two differ by padding and framing.
    ///
    /// `total` is 0 until the server has said how big it is, which is not known when a transfer
    /// starts — so the first report of any transfer is 0 of 0, meaning "beginning".
    int64_t done = 0;
    int64_t total = 0;

    /// Unset while it is running; set on exactly one report per transfer, the last, to success or
    /// to why it failed.  The error is the one the transfer's requester gets, with the same codes
    /// (see `err`), so a display showing progress needs no second vocabulary for how it ended.
    std::optional<Expected<void>> result;
};

/// What can be done about an attachment's bytes right now: read them, wait for them, fetch them, or
/// nothing at all.
///
/// What this is for is deciding what to *draw* -- the file, a progress indicator, something the
/// user can press to fetch it, or an explanation of why there is nothing to press -- so it is one
/// value rather than several a display would have to rank.  It says nothing the caller could not
/// eventually find out by asking for the bytes, but asking is how you start a download, and a
/// client with auto-download off needs to know before it decides whether to.
///
/// It is a *hint about what the next call will do*, not a promise about the file.  A `cached` that
/// is evicted before you ask for it just means `attachment_data` fetches instead of reading, which
/// is correct and merely slower.  Changes to it are reported through `messages_updated`, since this
/// is part of the message -- and for every message showing the same file at once, since it is one
/// file and one thing that happened to it.
///
/// **A switch over this needs a default.**  It may gain values, and a display that does not know
/// one should treat it as a file it cannot draw rather than guess.
enum class AttachmentAvailability {
    /// In the local cache: `attachment_data` will read it from disk without touching the network.
    cached,

    /// A transfer is already under way, whoever started it -- an auto-download, another message
    /// quoting the same file, or another part of the application.  `attachment_data` joins it
    /// rather than starting a second one, and reports progress from wherever it has reached.
    ///
    /// Except behind a `save_attachment` of a file too big for `requested_cache_max_size`: that
    /// writes straight to its destination and keeps nothing, so there is nothing to serve anyone
    /// joining partway, and `attachment_data` (or another save) fetches the file for itself.
    ///
    /// This outranks either failure below: a transfer running is about to settle the question,
    /// so what the last one found is not what to draw.
    fetching,

    /// Not here, and fetching it is worth trying, so `attachment_data` would start a download.
    /// With auto-download off, that is the case where the decision belongs to the user.
    absent,

    /// The last attempt found the file server does not hold it.  Usually an upload that has
    /// expired, which is the case that makes this worth reporting at all: the fix is in the
    /// sender's hands, so a display should say to ask them for it again rather than offer a button
    /// that cannot work.
    ///
    /// **A cached answer, not a fact about the url.**  An attachment url is a hash of the
    /// encrypted body and the encryption is deterministic, so the same file from the same account
    /// lands at the same url, and a re-upload puts those bytes back where they were.  That resend
    /// turns this back into `absent` -- for the original message as well as the new one, since it
    /// is the same file.
    not_found,

    /// The last attempt arrived and could not be read the way this message said to read it -- it
    /// failed to authenticate under the key it came with, or it is not the size its sender
    /// claimed.  A resend would reproduce the same bytes and the same failure, so "ask them to send
    /// it again" is not the advice here.
    ///
    /// A verdict on this message's key and size rather than on the file: another message naming
    /// the same url with a different key may read it perfectly well, and is not marked by this.
    unreadable,
};

struct Attachment {
    /// Position within the message's attachment list.  This is the index `send_message`'s upload
    /// handler reports progress against, and what `save_attachment` takes.
    size_t index;

    std::optional<std::string> content_type;
    std::optional<std::string> filename;

    /// A recorded voice message rather than an ordinary audio file, which clients present
    /// differently.
    bool voice_message = false;

    std::optional<uint32_t> width;
    std::optional<uint32_t> height;
    std::optional<std::vector<std::byte>> thumbhash;

    /// The file's size in bytes, before encryption -- what the file server holds is larger, since
    /// it carries the stream's per-chunk overhead and the padding that hides the true length.
    ///
    /// Unset on an outgoing attachment that has not been uploaded yet.  On an incoming one this is
    /// the sender's claim: for a legacy-encrypted attachment it is load-bearing, being what the
    /// padding is trimmed by, and a wrong value there shows up as a corrupt file.
    std::optional<int64_t> size;

    /// Whether the file is on the file server: for an outgoing attachment, that its upload
    /// finished, which is how a partly-uploaded message reports which of its files got through.
    /// Always true for an incoming attachment, which is where it came from.
    ///
    /// Where the file is *locally* is deliberately not here.  A local path is an argument to
    /// sending or saving, not a property of the attachment: the application chose it and knows it,
    /// and anything recorded here would go stale as soon as the file was moved.
    ///
    /// `availability` is not an exception to that.  The cache is ours, at a path derived from the
    /// url rather than chosen by anybody, so it is a fact about this attachment and not about
    /// somewhere the application happens to have put a copy.
    bool uploaded = false;

    /// Whether the bytes are here, on their way, fetchable, or not to be had -- see
    /// `AttachmentAvailability`.
    ///
    /// Reported the same way for an outgoing attachment as an incoming one: what we send is kept
    /// on upload under the rule that would have fetched it had it arrived, plus anything on a
    /// gallery-viewable message, which is drawn as its pictures and so needs them either way.  So
    /// "can I draw this without a download" has one answer regardless of direction.
    AttachmentAvailability availability = AttachmentAvailability::absent;

    /// How far the transfer has got, when `availability` is `fetching`; both 0 otherwise.
    ///
    /// The same figures, counting the same encrypted bytes, that `AttachmentProgress` carries, so
    /// a bar drawn from these and then fed by progress reports continues rather than jumping.
    /// `fetch_total` is 0 until the server has said how big it is, which is not known when a
    /// transfer starts.
    ///
    /// What these are for is a conversation opened while a download is already running: the
    /// reports went to whoever started it, and a display that missed them has no other way back to
    /// where it has reached.
    int64_t fetch_done = 0;
    int64_t fetch_total = 0;

    /// When the *recipient* of this message last saved this attachment -- us, on an incoming one,
    /// and the other party on one we sent.  The same fact from either end, so it does not have to
    /// be read differently depending on `Message::outgoing`.
    ///
    /// What it is for is knowing whether offering "save" again is pointless, and — on a message we
    /// sent — whether the file reached a person rather than merely a file server.
    ///
    /// Unset means **not known to have been saved**, which is not the same as not saved, and must
    /// not be shown as though it were.  On an outgoing attachment it depends entirely on the other
    /// end volunteering a notification: a client that sends none, or one too old to say which
    /// message it means, leaves this unset no matter how many times its user saved the file.  A
    /// sender reading an absent value as "they never got it" would be wrong.
    std::optional<sys_ms> saved_at;
};

}  // namespace session::client
