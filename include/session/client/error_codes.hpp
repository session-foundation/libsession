#pragma once

#include <string_view>

/// The `Error::code` values Client reports, named so that a caller comparing against one cannot be
/// defeated by a typo at either end, and so that adding one is a visible change rather than a new
/// string literal somewhere in a function body.
///
/// Dotted and grouped by the object that failed.  An open set: a caller that meets a code it does
/// not know falls back to the message, so this list growing is not a breaking change.
namespace session::client::err {

/// A name or nickname longer than the config will hold.  See `config::validate_contact_name`.
inline constexpr std::string_view name_too_long = "contacts.name_too_long";

/// No message has the id asked about.
inline constexpr std::string_view message_not_found = "message.not_found";

/// The message exists but has no attachment at the index asked about.
inline constexpr std::string_view attachment_not_found = "attachment.not_found";

/// The local file an outgoing attachment was made from is no longer there, so the message cannot
/// be sent.
inline constexpr std::string_view attachment_file_missing = "attachment.file_missing";

/// The file server does not have the file: it has expired, or was never there.  Only the sender
/// sending it again fixes this.  Matches `AttachmentAvailability::not_found`.
inline constexpr std::string_view file_not_found = "file.not_found";

/// The file cannot be read as its sender described it: there is no url, the key or digest is not
/// one the scheme can use, or the bytes do not decrypt, authenticate or match the size claimed.
/// Fetching it again gets the same bytes, so only a correct resend fixes this.  Matches
/// `AttachmentAvailability::unreadable`.
inline constexpr std::string_view file_unreadable = "file.unreadable";

/// A download failed for a reason that says nothing about the file -- a timeout, a server error, a
/// lost connection, or our own side -- so trying again may work.  The message says which.
inline constexpr std::string_view download_failed = "file.download_failed";

/// The request was withdrawn through `Client::cancel_attachment_transfer`, or because the
/// attachment it was for was deleted.
inline constexpr std::string_view download_cancelled = "file.download_cancelled";

/// An upload to the file server did not complete.  The message carries the status.
inline constexpr std::string_view upload_failed = "file.upload_failed";

/// A downloaded file could not be written where the caller asked for it.
inline constexpr std::string_view save_failed = "file.save_failed";

/// There is no network attached, so nothing that needs one can be done.
inline constexpr std::string_view network_unavailable = "network.unavailable";

}  // namespace session::client::err
