#include "session/attachments.hpp"

#include <nettle/aes.h>
#include <nettle/cbc.h>
#include <nettle/gcm.h>
#include <nettle/hmac.h>
#include <nettle/memops.h>
#include <nettle/sha2.h>
#include <session/attachments.h>
#include <sodium/crypto_core_hchacha20.h>
#include <sodium/crypto_secretstream_xchacha20poly1305.h>

#include <concepts>
#include <cstring>
#include <fstream>
#include <functional>
#include <limits>
#include <oxen/log.hpp>
#include <oxen/log/format.hpp>
#include <session/random.hpp>
#include <session/util.hpp>
#include <stdexcept>
#include <type_traits>

#include "internal-util.hpp"
#include "nettle-compat.hpp"
#include "session/hash.hpp"

namespace session::attachment {

using namespace oxen::log::literals;

static_assert(ENCRYPT_HEADER == crypto_secretstream_xchacha20poly1305_HEADERBYTES);
static_assert(ENCRYPT_CHUNK_OVERHEAD == crypto_secretstream_xchacha20poly1305_ABYTES);
static_assert(ENCRYPT_KEY_SIZE == crypto_secretstream_xchacha20poly1305_KEYBYTES);

size_t encrypted_padding(size_t data_size) {
    constexpr size_t prefix_size = 1 + ENCRYPT_HEADER;
    constexpr size_t min_padding = 1;

    // the number of mac+tag values embedded every 32kiB in the data stream:
    const size_t stream_chunks = (data_size + ENCRYPT_CHUNK_SIZE - 1) / ENCRYPT_CHUNK_SIZE;

    const size_t enc_size =
            data_size + prefix_size + min_padding + stream_chunks * ENCRYPT_CHUNK_OVERHEAD;

    const size_t pad_factor = std::bit_floor(std::max<size_t>(enc_size, 131072)) >> 5;

    // Round up to next multiple of pad_factor:
    const size_t padded_size = (enc_size + pad_factor - 1) / pad_factor * pad_factor;

    size_t padding = padded_size - enc_size + min_padding;

    // For every complete ENCRYPT_CHUNK_SIZE padding that we add we implicitly also add a stream
    // tag, and so we want to subtract one tag per (ENCRYPT_CHUNK_SIZE+ENCRYPT_CHUNK_OVERHEAD) bytes
    // of padding to compensate (so that the added tag gets counted as an implicit part of the
    // padding):
    size_t implicit_padding = 0;
    if (padding >= ENCRYPTED_CHUNK_TOTAL)
        implicit_padding = (padding / ENCRYPTED_CHUNK_TOTAL) * ENCRYPT_CHUNK_OVERHEAD;

    // After accounting for the full stream + tag blocks above, we might still have enough to spill
    // over the stream into the next chunk, and so if that is going to happen, we want to count the
    // implied additional tag as part of the padding as well.

    // This is how much padding we can add without spilling over into a new stream chunk:
    const size_t free_padding = stream_chunks * ENCRYPT_CHUNK_SIZE - data_size;

    if (padding % ENCRYPTED_CHUNK_TOTAL > free_padding)
        implicit_padding += ENCRYPT_CHUNK_OVERHEAD;

    padding -= implicit_padding;

    return padding;
}

size_t encrypted_size(size_t plaintext_size) {
    size_t padding = encrypted_padding(plaintext_size);
    size_t padded_size = plaintext_size + padding;
    size_t tags_size =
            (padded_size + ENCRYPT_CHUNK_SIZE - 1) / ENCRYPT_CHUNK_SIZE * ENCRYPT_CHUNK_OVERHEAD;

    return 1 /* 'S' identifier */ + ENCRYPT_HEADER + plaintext_size + padding + tags_size;
}

std::optional<size_t> decrypted_max_size(size_t encrypted_size) {
    size_t sz = encrypted_size - 1 /* 'S' identifier */ - 1 /* minimum padding length */ -
                ENCRYPT_HEADER;

    // The data is chunked into 32kiB+17B chunks (32kiB of data + 17 bytes of per-chunk stream
    // tag+mac), so we can figure out how many 17 byte overhead values should be present:
    size_t overhead =
            (sz + ENCRYPTED_CHUNK_TOTAL - 1) / ENCRYPTED_CHUNK_TOTAL * ENCRYPT_CHUNK_OVERHEAD;

    sz -= overhead;

    if (sz > encrypted_size)  // Overflow
        return std::nullopt;
    return sz;
}

class decryption_failure : public std::runtime_error {
  public:
    decryption_failure() :
            std::runtime_error{"Attachment decryption failed: invalid key or corrupted data"} {}
};

// We have to roll our own custom version of crypto_secretstream_xchacha20poly1305_init_push here
// because libsodium offers no way to provide the randomness it uses (it hard codes a call to
// randombytes_buf), and so this repeats its internal implementation but using our hashed data for
// the randomness.
static crypto_secretstream_xchacha20poly1305_state
secretstream_xchacha20poly1305_init_push_with_nonce(
        std::span<std::byte, ENCRYPT_HEADER> header,
        std::span<const std::byte, ENCRYPT_KEY_SIZE> key,
        std::span<const std::byte, ENCRYPT_HEADER> nonce) {

    crypto_secretstream_xchacha20poly1305_state st;

    std::memcpy(header.data(), nonce.data(), ENCRYPT_HEADER);
    crypto_core_hchacha20(st.k, to_unsigned(header.data()), to_unsigned(key.data()), nullptr);
    static_assert(sizeof(st) == 52);
    std::memset(st.nonce, 0, 4 /*crypto_secretstream_xchacha20poly1305_COUNTERBYTES*/);
    st.nonce[0] = 1;
    std::memcpy(
            st.nonce + 4 /*crypto_secretstream_xchacha20poly1305_COUNTERBYTES*/,
            header.data() + crypto_core_hchacha20_INPUTBYTES,
            8 /*crypto_secretstream_xchacha20poly1305_INONCEBYTES*/);
    std::memset(st._pad, 0, sizeof(st._pad));

    return st;
}

// Helper: creates an Encryptor from in-memory data, encrypts, and writes output into a span.
static std::pair<cleared_b32, size_t> encrypt_to_span(
        std::span<const std::byte> seed,
        std::span<const std::byte> data,
        Domain domain,
        std::span<std::byte> out,
        bool allow_large) {
    Encryptor enc{seed, domain};
    enc.update_key(data);

    size_t pos = 0;
    auto key = enc.start_encryption(
            [&](std::span<std::byte> buf) -> size_t {
                size_t avail = std::min(buf.size(), data.size() - pos);
                std::memcpy(buf.data(), data.data() + pos, avail);
                pos += avail;
                return avail;
            },
            allow_large);

    size_t written = 0;
    for (auto chunk = enc.next(); !chunk.empty(); chunk = enc.next()) {
        assert(written + chunk.size() <= out.size());
        std::memcpy(out.data() + written, chunk.data(), chunk.size());
        written += chunk.size();
    }

    return {std::move(key), written};
}

cleared_b32 encrypt(
        std::span<const std::byte> seed,
        std::span<const std::byte> data,
        Domain domain,
        std::span<std::byte> out,
        bool allow_large) {
    return encrypt_to_span(seed, data, domain, out, allow_large).first;
}

std::pair<std::vector<std::byte>, cleared_b32> encrypt(
        std::span<const std::byte> seed,
        std::span<const std::byte> data,
        Domain domain,
        bool allow_large) {
    std::vector<std::byte> out(encrypted_size(data.size()));
    auto key = encrypt_to_span(seed, data, domain, out, allow_large).first;
    return {std::move(out), std::move(key)};
}

cleared_b32 encrypt(
        std::span<const std::byte> seed,
        const std::filesystem::path& file,
        Domain domain,
        std::function<std::span<std::byte>(size_t enc_size)> make_buffer,
        bool allow_large) {
    auto [enc, key] = Encryptor::from_file(seed, domain, file, allow_large);

    auto out = make_buffer(encrypted_size(enc.data_size()));

    size_t written = 0;
    for (auto chunk = enc.next(); !chunk.empty(); chunk = enc.next()) {
        assert(written + chunk.size() <= out.size());
        std::memcpy(out.data() + written, chunk.data(), chunk.size());
        written += chunk.size();
    }

    return key;
}

std::pair<std::vector<std::byte>, cleared_b32> encrypt(
        std::span<const std::byte> seed,
        const std::filesystem::path& file,
        Domain domain,
        bool allow_large) {
    std::pair<std::vector<std::byte>, cleared_b32> result;
    auto& [encrypted, key] = result;

    key = encrypt(
            seed,
            file,
            domain,
            [&encrypted](size_t enc_size) {
                encrypted.resize(enc_size);
                return std::span{encrypted};
            },
            allow_large);

    return result;
}

cleared_b32 encrypt(
        std::span<const std::byte> seed,
        std::span<const std::byte> data,
        Domain domain,
        const std::filesystem::path& file,
        bool allow_large) {
    Encryptor enc{seed, domain};
    enc.update_key(data);

    size_t pos = 0;
    auto key = enc.start_encryption(
            [&](std::span<std::byte> buf) -> size_t {
                size_t avail = std::min(buf.size(), data.size() - pos);
                std::memcpy(buf.data(), data.data() + pos, avail);
                pos += avail;
                return avail;
            },
            allow_large);

    try {
        std::ofstream out;
        out.exceptions(std::ios::failbit | std::ios::badbit);
        out.open(file, std::ios::binary | std::ios::trunc);

        for (auto chunk = enc.next(); !chunk.empty(); chunk = enc.next())
            out.write(reinterpret_cast<const char*>(chunk.data()), chunk.size());
    } catch (const std::exception&) {
        std::error_code ec;
        std::filesystem::remove(file, ec);
        throw;
    }

    return key;
}

size_t decrypt(
        std::span<const std::byte> encrypted,
        std::span<const std::byte, ENCRYPT_KEY_SIZE> key,
        std::span<std::byte> out) {

    auto max_size = decrypted_max_size(encrypted.size());
    if (!max_size)
        throw std::runtime_error{"Attachment decryption failed: encrypted data too short"};

    if (encrypted.front() != std::byte{'S'})
        throw std::runtime_error{
                "Attachment decryption failed: unknown encryption type 0x{:02x}; expected 0x53 (S)"_format(
                        +static_cast<unsigned char>(encrypted.front()))};

    if (out.size() < *max_size)
        throw std::logic_error{
                "Attachment decryption failed: output buffer too small to decrypt contents"};

    auto uenc = encrypted;

    crypto_secretstream_xchacha20poly1305_state st;
    crypto_secretstream_xchacha20poly1305_init_pull(
            &st, to_unsigned(uenc.data() + 1), to_unsigned(key.data()));

    auto* inpos = uenc.data() + 1 + ENCRYPT_HEADER;
    auto* const inend = uenc.data() + uenc.size();

    std::byte* decrypted = out.data();
    bool done = false;

    // Discard any leading padding chunks (of which there is *always* at least 1 because we always
    // have at least one byte of padding, even for an empty file).  The last such chunk will
    // typically have the beginning of the actual data.  Once we figure out how much padding there
    // is we can calculate the remaining data and reserve the output buffer.
    {
        std::vector<std::byte> padbuf;
        padbuf.reserve(std::min(inend - inpos - ENCRYPT_CHUNK_OVERHEAD, ENCRYPT_CHUNK_SIZE));
        do {
            if (inpos + ENCRYPT_CHUNK_OVERHEAD >= inend)
                throw std::runtime_error{
                        "Attachment decryption failed: data ended in the middle of padding"};

            size_t chunk_size =
                    std::min(inend - inpos - ENCRYPT_CHUNK_OVERHEAD, ENCRYPT_CHUNK_SIZE);
            padbuf.resize(chunk_size);

            unsigned char tag;
            if (crypto_secretstream_xchacha20poly1305_pull(
                        &st,
                        reinterpret_cast<unsigned char*>(padbuf.data()),
                        nullptr,
                        &tag,
                        to_unsigned(inpos),
                        chunk_size + ENCRYPT_CHUNK_OVERHEAD,
                        nullptr,
                        0) != 0)
                throw std::runtime_error{
                        "Attachment decryption failed: invalid key or corrupted data"};

            inpos += chunk_size + ENCRYPT_CHUNK_OVERHEAD;

            auto padend = std::find_if_not(padbuf.begin(), padbuf.end(), [](const std::byte c) {
                return c == std::byte{0x00};
            });
            if (padend != padbuf.end()) {
                if (*padend != std::byte{0x01})
                    throw std::runtime_error{"Attachment decryption failed: invalid padding"};
                ++padend;

                std::span<const std::byte> init_data{padend, padbuf.end()};
                // We've identified the start of the data: assuming it is valid, the remaining of
                // the encrypted data consists of N chunks of
                // (ENCRYPT_CHUNK_SIZE+ENCRYPT_CHUNK_OVERHEAD) full data chunks plus one final
                // (chunk+ENCRYPT_CHUNK_OVERHEAD).
                size_t final_size = init_data.size() + (inend - inpos) -
                                    (inend - inpos + ENCRYPTED_CHUNK_TOTAL - 1) /
                                            ENCRYPTED_CHUNK_TOTAL * ENCRYPT_CHUNK_OVERHEAD;
                assert(out.size() >= final_size);
                decrypted = std::copy(padend, padbuf.end(), decrypted);

                if (tag == crypto_secretstream_xchacha20poly1305_TAG_FINAL) {
                    if (inpos != inend)
                        throw std::runtime_error{
                                "Attachment decryption failed: FINAL tag before end of the "
                                "encrypted data"};
                    done = true;
                } else if (
                        inpos == inend && tag != crypto_secretstream_xchacha20poly1305_TAG_FINAL) {
                    throw std::runtime_error{
                            "Attachment decryption failed: end of data without FINAL tag"};
                }

                break;
            }
        } while (true);
    }

    while (!done) {
        if (inpos + ENCRYPT_CHUNK_OVERHEAD >= inend)
            throw std::runtime_error{
                    "Attachment decryption failed: data ended before end of stream"};

        size_t chunk_size = std::min(inend - inpos - ENCRYPT_CHUNK_OVERHEAD, ENCRYPT_CHUNK_SIZE);
        assert(decrypted + chunk_size <= out.data() + out.size());

        unsigned char tag;
        if (crypto_secretstream_xchacha20poly1305_pull(
                    &st,
                    reinterpret_cast<unsigned char*>(decrypted),
                    nullptr,
                    &tag,
                    to_unsigned(inpos),
                    chunk_size + ENCRYPT_CHUNK_OVERHEAD,
                    nullptr,
                    0) != 0)
            throw std::runtime_error{"Attachment decryption failed: invalid key or corrupted data"};

        decrypted += chunk_size;
        inpos += chunk_size + ENCRYPT_CHUNK_OVERHEAD;

        if (tag == crypto_secretstream_xchacha20poly1305_TAG_FINAL) {
            if (inpos != inend)
                throw std::runtime_error{
                        "Attachment decryption failed: FINAL tag before end of the "
                        "encrypted data"};
            done = true;
        } else if (inpos == inend && tag != crypto_secretstream_xchacha20poly1305_TAG_FINAL) {
            throw std::runtime_error{"Attachment decryption failed: end of data without FINAL tag"};
        }
    }

    return decrypted - out.data();
}

std::vector<std::byte> decrypt(
        std::span<const std::byte> encrypted, std::span<const std::byte, ENCRYPT_KEY_SIZE> key) {

    auto max_size = decrypted_max_size(encrypted.size());
    if (!max_size)
        throw std::runtime_error{"Attachment decryption failed: encrypted data too short"};

    if (encrypted.front() != std::byte{'S'})
        throw std::runtime_error{
                "Attachment decryption failed: unknown encryption type 0x{:02x}; expected 0x53 (S)"_format(
                        +static_cast<unsigned char>(encrypted.front()))};

    std::vector<std::byte> result;
    result.resize(*max_size);

    size_t actual = decrypt(encrypted, key, result);
    result.resize(actual);

    return result;
}

std::vector<std::byte> legacy_display_pic_decrypt(
        std::span<const std::byte> encrypted,
        std::span<const std::byte, LEGACY_DISPLAY_PIC_KEY_SIZE> key) {

    if (encrypted.size() <= LEGACY_DISPLAY_PIC_NONCE_SIZE + LEGACY_DISPLAY_PIC_TAG_SIZE)
        throw std::runtime_error{
                "Display picture decryption failed: {} bytes cannot hold a nonce, a tag and any "
                "data"_format(encrypted.size())};

    struct gcm_aes256_ctx ctx;
    gcm_aes256_set_key(&ctx, to_unsigned(key.data()));
    gcm_aes256_set_iv(&ctx, LEGACY_DISPLAY_PIC_NONCE_SIZE, to_unsigned(encrypted.data()));

    auto body = encrypted.subspan(LEGACY_DISPLAY_PIC_NONCE_SIZE);
    auto tag_in = body.subspan(body.size() - LEGACY_DISPLAY_PIC_TAG_SIZE);
    body = body.subspan(0, body.size() - LEGACY_DISPLAY_PIC_TAG_SIZE);

    std::vector<std::byte> plaintext(body.size());
    gcm_aes256_decrypt(&ctx, body.size(), to_unsigned(plaintext.data()), to_unsigned(body.data()));

    std::array<unsigned char, LEGACY_DISPLAY_PIC_TAG_SIZE> tag_out;
    nettle_digest<gcm_aes256_digest>(&ctx, tag_out.size(), tag_out.data());

    // Constant time, as everywhere else a MAC is compared: leaking where two tags first differ is
    // what lets an attacker find a valid one a byte at a time.
    if (sodium_memcmp(tag_out.data(), tag_in.data(), LEGACY_DISPLAY_PIC_TAG_SIZE) != 0)
        throw std::runtime_error{"Display picture decryption failed: bad tag"};

    return plaintext;
}

std::vector<std::byte> legacy_decrypt(
        std::span<const std::byte> encrypted,
        std::span<const std::byte, LEGACY_KEY_SIZE> key,
        // Still taken, and still required to be the right length by callers, because every other
        // client needs one sent; see below for why nothing here reads it.
        [[maybe_unused]] std::span<const std::byte, LEGACY_DIGEST_SIZE> digest,
        size_t unpadded_size) {

    // Bounded by what the file server will actually store, so a caller cannot be talked into
    // holding an arbitrary amount by anything a sender claims.  This has to be all in memory: the
    // authenticators below cover the whole ciphertext, and nothing may be decrypted until they
    // pass.
    if (encrypted.size() > LEGACY_MAX_ENCRYPTED_SIZE)
        throw std::runtime_error{
                "Legacy attachment decryption failed: {}B exceeds the {}B maximum"_format(
                        encrypted.size(), LEGACY_MAX_ENCRYPTED_SIZE)};

    if (encrypted.size() < LEGACY_IV_SIZE + AES_BLOCK_SIZE + LEGACY_MAC_SIZE)
        throw std::runtime_error{"Legacy attachment decryption failed: encrypted data too short"};

    auto body_size = encrypted.size() - LEGACY_IV_SIZE - LEGACY_MAC_SIZE;
    if (body_size % AES_BLOCK_SIZE != 0)
        throw std::runtime_error{
                "Legacy attachment decryption failed: ciphertext is not a whole number of blocks"};

    auto iv = encrypted.first<LEGACY_IV_SIZE>();
    auto body = encrypted.subspan(LEGACY_IV_SIZE, body_size);
    auto mac = encrypted.last<LEGACY_MAC_SIZE>();
    // What both authenticators are computed over: everything but the trailing MAC itself.
    auto authenticated = encrypted.first(LEGACY_IV_SIZE + body_size);

    std::array<std::byte, LEGACY_MAC_SIZE> expected_mac;
    {
        hmac_sha256_ctx ctx;
        hmac_sha256_set_key(&ctx, 32, to_unsigned(key.data()) + 32);
        hmac_sha256_update(&ctx, authenticated.size(), to_unsigned(authenticated.data()));
        nettle_digest<hmac_sha256_digest>(
                &ctx, expected_mac.size(), to_unsigned(expected_mac.data()));
    }
    if (!memeql_sec(expected_mac.data(), mac.data(), LEGACY_MAC_SIZE))
        throw std::runtime_error{"Legacy attachment decryption failed: HMAC mismatch"};

    // Not verified, deliberately.  The pointer also carries a SHA-256 over the whole blob -- IV,
    // ciphertext and the MAC above -- which every other Session client requires and checks, and
    // which is worth nothing here.
    //
    // The HMAC just verified covers the same bytes under a key that only the sender has.  The
    // digest is keyless and travels in the same pointer as that key, so it is not a second opinion
    // from a second party: anyone able to forge one could forge both, and any alteration that would
    // fail it -- substituted file, tampered ciphertext, truncation, a rewritten MAC -- fails the
    // HMAC first and never reaches this. It catches nothing the line above did not already catch,
    // at the cost of hashing the entire attachment a second time.
    //
    // It exists because Session inherited Signal's attachment pointer whole, where a digest served
    // purposes Session does not have.  We still *send* one, and still require the field to be
    // present and the right length, because the other clients fail without it -- and iOS does worse
    // than fail, writing the ciphertext to disk as though it were the file.
    //
    // Left here rather than deleted so that the reasoning is visible next to what it is about, and
    // so restoring it is a matter of removing comment markers if that reasoning ever turns out to
    // be wrong.
    //
    // std::array<std::byte, LEGACY_DIGEST_SIZE> expected_digest;
    // {
    //     sha256_ctx ctx;
    //     sha256_init(&ctx);
    //     sha256_update(&ctx, encrypted.size(), to_unsigned(encrypted.data()));
    //     nettle_digest<sha256_digest>(
    //             &ctx, expected_digest.size(), to_unsigned(expected_digest.data()));
    // }
    // if (!memeql_sec(expected_digest.data(), digest.data(), LEGACY_DIGEST_SIZE))
    //     throw std::runtime_error{"Legacy attachment decryption failed: digest mismatch"};

    std::vector<std::byte> plaintext;
    plaintext.resize(body_size);
    {
        aes256_ctx ctx;
        aes256_set_decrypt_key(&ctx, to_unsigned(key.data()));
        // cbc_decrypt consumes the IV in place, so it gets a copy rather than the input span.
        std::array<uint8_t, LEGACY_IV_SIZE> iv_copy;
        std::memcpy(iv_copy.data(), iv.data(), iv_copy.size());
        cbc_decrypt(
                &ctx,
                reinterpret_cast<nettle_cipher_func*>(aes256_decrypt),
                AES_BLOCK_SIZE,
                iv_copy.data(),
                body_size,
                to_unsigned(plaintext.data()),
                to_unsigned(body.data()));
    }

    // PKCS#7: the last byte is how many padding bytes there are, and every one of them must say so.
    // Nettle leaves this to us, unlike the platform APIs the other clients decrypt with.
    auto pad = static_cast<size_t>(plaintext.back());
    if (pad == 0 || pad > AES_BLOCK_SIZE || pad > plaintext.size())
        throw std::runtime_error{"Legacy attachment decryption failed: bad PKCS#7 padding"};
    for (auto it = plaintext.end() - pad; it != plaintext.end(); ++it)
        if (static_cast<size_t>(*it) != pad)
            throw std::runtime_error{"Legacy attachment decryption failed: bad PKCS#7 padding"};
    plaintext.resize(plaintext.size() - pad);

    // Session's own zero padding, on top of the block padding, is what `unpadded_size` describes.
    // Zero means the sender never said -- only clients older than the field do that -- and the
    // padding stays rather than being guessed at.
    if (unpadded_size > 0) {
        if (unpadded_size > plaintext.size())
            throw std::runtime_error{
                    "Legacy attachment decryption failed: claimed size {}B exceeds the {}B decrypted"_format(
                            unpadded_size, plaintext.size())};

        // What follows the claimed length is *not* checked, and cannot be.  Our own encryptor pads
        // with zeroes, but session-android's PaddingInputStream does not: its bulk read reports
        // having produced `length` padding bytes without writing anything into the buffer, so the
        // padding is whatever the caller's buffer already held.  Only its single-byte read() emits
        // 0x00, and nothing reads a file a byte at a time.
        //
        // So an attachment from Android is padded with arbitrary bytes, and requiring zeroes here
        // would reject every one of them.  Under-reporting therefore still truncates silently; the
        // legacy format gives us nothing to catch it with.
        plaintext.resize(unpadded_size);
    }

    return plaintext;
}

Decryptor::Decryptor(
        std::span<const std::byte, ENCRYPT_KEY_SIZE> key_,
        std::function<void(std::span<const std::byte> decrypted)> output_) :
        output{std::move(output_)} {

    std::memcpy(key.data(), key_.data(), key.size());

    static_assert(
            sizeof(crypto_secretstream_xchacha20poly1305_state) == sizeof(Decryptor::st_data));
    static_assert(alignof(crypto_secretstream_xchacha20poly1305_state) == 1);
    static_assert(std::is_trivially_copyable_v<crypto_secretstream_xchacha20poly1305_state>);
}

static crypto_secretstream_xchacha20poly1305_state* st(unsigned char* st_data) {
    return reinterpret_cast<crypto_secretstream_xchacha20poly1305_state*>(st_data);
}
void Decryptor::process_header(std::span<const std::byte, 1 + ENCRYPT_HEADER> hdr) {
    assert(!header);

    if (hdr[0] != std::byte{'S'}) {
        failed = true;
        return;
    }

    crypto_secretstream_xchacha20poly1305_init_pull(
            st(st_data),
            reinterpret_cast<const unsigned char*>(hdr.data() + 1),
            reinterpret_cast<const unsigned char*>(key.data()));
    header = true;
}

void Decryptor::process_chunk(std::span<const std::byte> chunk, [[maybe_unused]] bool is_final) {
    if (hit_final) {
        failed = true;
        return;
    }
    assert(is_final || chunk.size() == ENCRYPTED_CHUNK_TOTAL);
    assert(chunk.size() <= ENCRYPTED_CHUNK_TOTAL);
    if (chunk.size() < ENCRYPT_CHUNK_OVERHEAD) {
        failed = true;
        return;
    }

    unsigned char tag;
    std::array<std::byte, ENCRYPT_CHUNK_SIZE> outa;
    std::span out{outa.data(), chunk.size() - ENCRYPT_CHUNK_OVERHEAD};
    if (crypto_secretstream_xchacha20poly1305_pull(
                st(st_data),
                reinterpret_cast<unsigned char*>(out.data()),
                nullptr,
                &tag,
                reinterpret_cast<const unsigned char*>(chunk.data()),
                chunk.size(),
                nullptr,
                0) != 0) {
        failed = true;
        return;
    }

    if (tag == crypto_secretstream_xchacha20poly1305_TAG_FINAL)
        hit_final = true;

    if (!depadded) {
        auto padend = std::find_if_not(
                out.begin(), out.end(), [](const std::byte c) { return c == std::byte{0x00}; });
        if (padend == out.end()) {
            padding_seen += out.size();
            return;
        }
        if (*padend != std::byte{0x01}) {
            failed = true;
            return;
        }
        ++padend;
        padding_seen += static_cast<size_t>(padend - out.begin());
        depadded = true;
        if (padend != out.end())
            output(std::span<const std::byte>{padend, out.end()});
        return;
    }

    output(out);
}

[[nodiscard]] bool Decryptor::update(std::span<const std::byte> enc_data) {
    if (failed)
        return false;
    if (finished)
        throw std::logic_error{"cannot call update after finalize()"};

    if (!buf.empty()) {
        auto buf_steal = [this, &enc_data](size_t target_buf_size) {
            assert(buf.size() < target_buf_size);
            size_t steal = std::min(target_buf_size - buf.size(), enc_data.size());
            buf.insert(buf.end(), enc_data.begin(), enc_data.begin() + steal);
            enc_data = enc_data.subspan(steal);
            assert(buf.size() <= target_buf_size);
            return buf.size() == target_buf_size;
        };

        if (!header) {
            if (!buf_steal(1 + ENCRYPT_HEADER))
                return true;
            process_header(std::span{buf}.first<1 + ENCRYPT_HEADER>());
        } else {
            if (!buf_steal(ENCRYPTED_CHUNK_TOTAL))
                return true;
            process_chunk(std::span{buf}.first<ENCRYPTED_CHUNK_TOTAL>());
        }
        buf.clear();
        if (failed)
            return false;
    }

    if (!header) {
        if (enc_data.size() >= 1 + ENCRYPT_HEADER) {
            process_header(enc_data.first<1 + ENCRYPT_HEADER>());
            if (failed)
                return false;
            enc_data = enc_data.subspan(1 + ENCRYPT_HEADER);
        } else {
            buf.assign(enc_data.begin(), enc_data.end());
            return true;
        }
    }

    while (enc_data.size() >= ENCRYPTED_CHUNK_TOTAL) {
        process_chunk(enc_data.first<ENCRYPTED_CHUNK_TOTAL>());
        if (failed)
            return false;
        enc_data = enc_data.subspan(ENCRYPTED_CHUNK_TOTAL);
    }

    if (!enc_data.empty())
        buf.assign(enc_data.begin(), enc_data.end());

    return true;
}

[[nodiscard]] bool Decryptor::finalize() {
    if (failed)
        return false;

    if (!buf.empty()) {
        process_chunk(buf, true);
        buf.clear();
    }

    if (failed)
        return false;

    if (!hit_final) {
        failed = true;
        return false;
    }

    return true;
}

std::optional<size_t> Decryptor::padding() const {
    if (!depadded)
        return std::nullopt;
    return padding_seen;
}

PushEncryptor::PushEncryptor(
        std::span<const std::byte, ENCRYPT_KEY_SIZE> key,
        size_t padding,
        std::function<void(std::span<const std::byte> encrypted)> output_) :
        output{std::move(output_)} {
    if (padding < 1)
        throw std::invalid_argument{"PushEncryptor: padding counts its marker, so is at least 1"};

    static_assert(
            sizeof(crypto_secretstream_xchacha20poly1305_state) == sizeof(PushEncryptor::st_data));

    std::array<std::byte, 1 + ENCRYPT_HEADER> header;
    header[0] = std::byte{'S'};
    crypto_secretstream_xchacha20poly1305_init_push(
            st(st_data), to_unsigned(header.data() + 1), to_unsigned(key.data()));
    output(header);

    // A chunk at a time, so that the padding of a large file -- which can be many chunks -- is
    // never held whole.
    for (size_t zeros = padding - 1; zeros > 0;) {
        auto n = std::min(zeros, ENCRYPT_CHUNK_SIZE);
        buf.insert(buf.end(), n, std::byte{0});
        zeros -= n;
        while (buf.size() > ENCRYPT_CHUNK_SIZE)
            push(ENCRYPT_CHUNK_SIZE, false);
    }
    buf.push_back(std::byte{0x01});
}

void PushEncryptor::update(std::span<const std::byte> data) {
    if (finished)
        throw std::logic_error{"PushEncryptor::update() called after finalize()"};

    // Strictly more than a chunk before one goes, so that a full one is always held back: whether
    // it is the last is only known at finalize(), and the last carries the final tag.
    while (!data.empty()) {
        auto n = std::min(data.size(), ENCRYPT_CHUNK_SIZE);
        buf.insert(buf.end(), data.begin(), data.begin() + static_cast<ptrdiff_t>(n));
        data = data.subspan(n);
        while (buf.size() > ENCRYPT_CHUNK_SIZE)
            push(ENCRYPT_CHUNK_SIZE, false);
    }
}

void PushEncryptor::finalize() {
    if (finished)
        throw std::logic_error{"PushEncryptor::finalize() called twice"};
    // Never empty: the marker alone guarantees a byte, and update() always holds some back.
    push(buf.size(), true);
    finished = true;
}

void PushEncryptor::push(size_t size, bool is_final) {
    std::array<std::byte, ENCRYPTED_CHUNK_TOTAL> out;
    unsigned long long len;
    crypto_secretstream_xchacha20poly1305_push(
            st(st_data),
            to_unsigned(out.data()),
            &len,
            to_unsigned(buf.data()),
            size,
            nullptr,
            0,
            is_final ? crypto_secretstream_xchacha20poly1305_TAG_FINAL : 0);
    buf.erase(buf.begin(), buf.begin() + static_cast<ptrdiff_t>(size));
    output(std::span<const std::byte>{out.data(), static_cast<size_t>(len)});
}

void decrypt(
        std::span<const std::byte> encrypted,
        std::span<const std::byte, ENCRYPT_KEY_SIZE> key,
        const std::filesystem::path& filename) {

    try {
        std::ofstream out;
        out.exceptions(std::ios::failbit | std::ios::badbit);
        out.open(filename, std::ios::binary | std::ios::out | std::ios::trunc);
        Decryptor d{key, [&out](std::span<const std::byte> data) {
                        out.write(reinterpret_cast<const char*>(data.data()), data.size());
                    }};

        if (!d.update(encrypted) || !d.finalize())
            throw decryption_failure{};
    } catch (const std::exception& e) {
        std::error_code ec;
        std::filesystem::remove(filename, ec);
        throw;
    }
}

size_t decrypt(
        const std::filesystem::path& encrypted_file,
        std::span<const std::byte, ENCRYPT_KEY_SIZE> key,
        std::function<std::span<std::byte>(size_t dec_size)> make_buffer) {

    std::ifstream in;
    in.exceptions(std::ios::badbit);
    in.open(encrypted_file, std::ios::binary | std::ios::ate);
    size_t size = in.tellg();
    in.seekg(0, std::ios::beg);

    auto max_size = decrypted_max_size(size);
    if (!max_size)
        throw std::runtime_error{
                "Decryption failed: file is too small to contain an encrypted attachment"};
    auto out = make_buffer(*max_size);
    if (out.size() != *max_size)
        throw std::logic_error{
                "make_buffer returned span of invalid size: expected {}, got {}"_format(
                        *max_size, out.size())};

    auto decrypted = out.begin();
    auto end = out.end();
    Decryptor d{key, [&decrypted, &end](std::span<const std::byte> data) {
                    if (data.size() > end - decrypted)
                        throw std::runtime_error{
                                "Decryption failed: output span is too small to contain decrypted "
                                "data"};
                    decrypted = std::copy(data.begin(), data.end(), decrypted);
                }};

    std::array<std::byte, 4096> chunk;
    while (in.read(reinterpret_cast<char*>(chunk.data()), chunk.size())) {
        if (!d.update(chunk))
            throw decryption_failure{};
    }
    if (in.gcount() > 0 && !d.update(std::span{chunk}.first(in.gcount())))
        throw decryption_failure{};

    if (!d.finalize())
        throw decryption_failure{};

    return decrypted - out.begin();
}

std::vector<std::byte> decrypt(
        const std::filesystem::path& encrypted_file,
        std::span<const std::byte, ENCRYPT_KEY_SIZE> key) {

    std::vector<std::byte> plaintext;
    size_t actual = decrypt(encrypted_file, key, [&plaintext](size_t size) {
        plaintext.resize(size);
        return std::span{plaintext};
    });
    plaintext.resize(actual);
    return plaintext;
}

void decrypt(
        const std::filesystem::path& file_in,
        std::span<const std::byte, ENCRYPT_KEY_SIZE> key,
        const std::filesystem::path& file_out) {

    try {
        std::ifstream in;
        in.exceptions(std::ios::badbit);
        in.open(file_in, std::ios::binary | std::ios::ate);
        size_t size = in.tellg();
        in.seekg(0, std::ios::beg);

        auto max_size = decrypted_max_size(size);
        if (!max_size)
            throw std::runtime_error{
                    "Decryption failed: file is too small to contain an encrypted attachment"};

        std::ofstream out;
        out.exceptions(std::ios::failbit | std::ios::badbit);
        out.open(file_out, std::ios::binary | std::ios::trunc);

        Decryptor d{key, [&out](std::span<const std::byte> data) {
                        out.write(reinterpret_cast<const char*>(data.data()), data.size());
                    }};

        std::array<std::byte, 4096> chunk;
        while (in.read(reinterpret_cast<char*>(chunk.data()), chunk.size())) {
            if (!d.update(chunk))
                throw decryption_failure{};
        }
        if (in.gcount() > 0 && !d.update(std::span{chunk}.first(in.gcount())))
            throw decryption_failure{};
        if (!d.finalize())
            throw decryption_failure{};
    } catch (const std::exception& e) {
        std::error_code ec;
        std::filesystem::remove(file_out, ec);
        throw;
    }
}

// -- Encryptor --

static_assert(
        sizeof(crypto_generichash_blake2b_state) == 384 &&
                alignof(crypto_generichash_blake2b_state) == 64,
        "blake2b state size/alignment changed; update Encryptor::hash_st_data");

static_assert(
        sizeof(crypto_secretstream_xchacha20poly1305_state) == 52,
        "secretstream state size changed; update Encryptor::ss_st_data");

namespace {
    using namespace session::literals;

    constexpr auto PERS_ATTACHMENT = "SessionAttachmnt"_b2b_pers;
    constexpr auto PERS_PROFILE_PIC = "Session_Prof_Pic"_b2b_pers;

    const auto& domain_pers(Domain domain) {
        switch (domain) {
            case Domain::ATTACHMENT: return PERS_ATTACHMENT;
            case Domain::PROFILE_PIC: return PERS_PROFILE_PIC;
        }
        throw std::invalid_argument{"Invalid encryption domain"};
    }

    auto& b2b_st(std::byte (&data)[384]) {
        return *reinterpret_cast<crypto_generichash_blake2b_state*>(data);
    }
    auto& ss_st(std::byte (&data)[52]) {
        return *reinterpret_cast<crypto_secretstream_xchacha20poly1305_state*>(data);
    }
    auto* uc(std::byte* p) {
        return reinterpret_cast<unsigned char*>(p);
    }
    auto* uc(const std::byte* p) {
        return reinterpret_cast<const unsigned char*>(p);
    }
}  // namespace

Encryptor::Encryptor(std::span<const std::byte> seed, Domain domain) {
    if (seed.size() < 32)
        throw std::invalid_argument{"attachment::Encryptor requires a 32-byte uploader seed"};

    const auto& pers = domain_pers(domain);
    crypto_generichash_blake2b_init_salt_personal(
            &b2b_st(hash_st_data), uc(seed.data()), 32, nonce_key.size(), nullptr, uc(pers.data()));
}

Encryptor::Encryptor(std::span<const std::byte, ENCRYPT_KEY_SIZE> key) : key_given{true} {
    // The layout the seed-based path derives: nonce first, then key.  Here the key is given and the
    // nonce is random, because one key encrypts everything we cache and a repeated nonce under a
    // repeated key repeats the keystream.
    random::fill(std::span{nonce_key.data(), ENCRYPT_HEADER});
    std::memcpy(nonce_key.data() + ENCRYPT_HEADER, key.data(), ENCRYPT_KEY_SIZE);
}

void Encryptor::update_key(std::span<const std::byte> data) {
    if (key_given)
        throw std::logic_error{"Encryptor::update_key() called on a fixed-key encryptor"};
    if (phase1_done)
        throw std::logic_error{"Encryptor::update() called after start_encryption()"};

    crypto_generichash_blake2b_update(&b2b_st(hash_st_data), uc(data.data()), data.size());
    hashed_size += data.size();
}

cleared_b32 Encryptor::start_encryption(
        std::function<size_t(std::span<std::byte> buffer)> src,
        bool allow_large,
        std::optional<size_t> enc_size) {
    if (phase1_done)
        throw std::logic_error{"start_encryption() called twice"};
    phase1_done = true;

    // With a key of our own there is no hash to finalize; nonce_key was filled at construction.
    if (!key_given)
        crypto_generichash_blake2b_final(
                &b2b_st(hash_st_data), uc(nonce_key.data()), nonce_key.size());
    else if (!enc_size)
        throw std::invalid_argument{
                "start_encryption() on a fixed-key encryptor requires encrypt_size: nothing "
                "hashed the data to know how much is coming"};

    cleared_b32 key;
    std::memcpy(key.data(), nonce_key.data() + ENCRYPT_HEADER, ENCRYPT_KEY_SIZE);

    encrypt_size = enc_size.value_or(hashed_size);

    if (encrypt_size > MAX_REGULAR_SIZE && !allow_large)
        throw std::invalid_argument{"data to encrypt is too large"};

    source = std::move(src);
    padding = encrypted_padding(encrypt_size);
    padding_remaining = padding;

    // Write 'S' prefix + header into out_buf; initialize secretstream
    out_buf[0] = std::byte{'S'};
    ss_st(ss_st_data) = secretstream_xchacha20poly1305_init_push_with_nonce(
            std::span<std::byte, ENCRYPT_HEADER>{out_buf.data() + 1, ENCRYPT_HEADER},
            std::span<const std::byte, ENCRYPT_KEY_SIZE>{
                    nonce_key.data() + ENCRYPT_HEADER, ENCRYPT_KEY_SIZE},
            std::span<const std::byte, ENCRYPT_HEADER>{nonce_key.data(), ENCRYPT_HEADER});
    out_size = 1 + ENCRYPT_HEADER;

    plaintext_buf.reserve(ENCRYPT_CHUNK_SIZE);

    return key;
}

bool Encryptor::produce_next() {
    if (done)
        return false;
    if (!source)
        throw std::logic_error{"Encryptor::next() requires a data source"};

    plaintext_buf.clear();

    size_t need = ENCRYPT_CHUNK_SIZE;

    // Fill with padding first
    if (padding_remaining > 0) {
        if (padding_remaining > ENCRYPT_CHUNK_SIZE) {
            plaintext_buf.resize(ENCRYPT_CHUNK_SIZE, std::byte{0});
            padding_remaining -= ENCRYPT_CHUNK_SIZE;
            need = 0;
        } else {
            plaintext_buf.resize(padding_remaining - 1, std::byte{0});
            plaintext_buf.push_back(std::byte{0x01});
            need = ENCRYPT_CHUNK_SIZE - padding_remaining;
            padding_remaining = 0;
        }
    }

    // Fill the rest from the data source
    if (need > 0) {
        size_t before = plaintext_buf.size();
        plaintext_buf.resize(before + need);
        size_t got = source(std::span{plaintext_buf}.subspan(before, need));
        plaintext_buf.resize(before + got);
        encrypted_so_far += got;

        bool source_done = got < need;

        if (encrypted_so_far > encrypt_size)
            throw std::runtime_error{
                    "Encryptor data source provided too much data: expected {} bytes, got at least {}"_format(
                            encrypt_size, encrypted_so_far)};

        if (source_done && encrypted_so_far < encrypt_size)
            throw std::runtime_error{
                    "Encryptor data source ended prematurely: expected {} bytes, got {}"_format(
                            encrypt_size, encrypted_so_far)};
    }

    if (plaintext_buf.empty()) {
        done = true;
        return false;
    }

    bool is_final = encrypted_so_far >= encrypt_size && padding_remaining == 0;
    unsigned char tag = is_final ? crypto_secretstream_xchacha20poly1305_TAG_FINAL : 0;

    unsigned long long enc_len;
    crypto_secretstream_xchacha20poly1305_push(
            &ss_st(ss_st_data),
            uc(out_buf.data()),
            &enc_len,
            uc(plaintext_buf.data()),
            plaintext_buf.size(),
            nullptr,
            0,
            tag);
    out_size = static_cast<size_t>(enc_len);

    if (is_final)
        done = true;

    return true;
}

std::span<const std::byte> Encryptor::next() {
    if (!phase1_done)
        throw std::logic_error{"Encryptor::next() called before start_encryption()"};

    // First call returns the 'S' prefix + header
    if (!header_emitted) {
        header_emitted = true;
        return {out_buf.data(), out_size};
    }

    if (!produce_next())
        return {};

    return {out_buf.data(), out_size};
}

cleared_b32 Encryptor::load_key_from_file(
        const std::filesystem::path& file,
        bool allow_large,
        std::function<void(int64_t bytes_read, int64_t total_size)> progress) {
    auto in = std::make_shared<std::ifstream>();
    in->exceptions(std::ios::badbit);
    in->open(file, std::ios::binary | std::ios::ate);
    int64_t total = in->tellg();
    in->seekg(0, std::ios::beg);

    // Phase 1: hash the file
    constexpr size_t READ_SIZE = 65536;
    std::vector<std::byte> chunk(READ_SIZE);
    int64_t read_so_far = 0;
    while (in->read(reinterpret_cast<char*>(chunk.data()), chunk.size())) {
        update_key(chunk);
        read_so_far += chunk.size();
        if (progress)
            progress(read_so_far, total);
    }
    if (in->gcount() > 0) {
        update_key(std::span{chunk}.first(in->gcount()));
        read_so_far += in->gcount();
        if (progress)
            progress(read_so_far, total);
    }

    // Seek back for phase 2
    in->clear();
    in->seekg(0, std::ios::beg);

    return start_encryption(
            [in](std::span<std::byte> buffer) -> size_t {
                in->read(reinterpret_cast<char*>(buffer.data()), buffer.size());
                return in->gcount();
            },
            allow_large);
}

std::pair<Encryptor, cleared_b32> Encryptor::from_file(
        std::span<const std::byte> seed,
        Domain domain,
        const std::filesystem::path& file,
        bool allow_large) {
    Encryptor enc{seed, domain};
    auto key = enc.load_key_from_file(file, allow_large);
    return {std::move(enc), std::move(key)};
}

}  // namespace session::attachment

extern "C" {

using namespace session;

const size_t ATTACHMENT_ENCRYPT_KEY_SIZE = attachment::ENCRYPT_KEY_SIZE;
const size_t ATTACHMENT_MAX_REGULAR_SIZE = attachment::MAX_REGULAR_SIZE;

LIBSESSION_C_API size_t session_attachment_encrypted_size(size_t plaintext_len) {
    return attachment::encrypted_size(plaintext_len);
}

LIBSESSION_C_API size_t session_attachment_decrypted_max_size(size_t encrypted_len) {
    return attachment::decrypted_max_size(encrypted_len)
            .value_or(std::numeric_limits<size_t>::max());
}

LIBSESSION_C_API bool session_attachment_encrypt(
        const unsigned char* seed,
        const unsigned char* data,
        size_t datalen,
        ATTACHMENT_DOMAIN domain,
        unsigned char* key_out,
        unsigned char* out,
        char* error) {
    try {
        auto key = attachment::encrypt(
                std::span{reinterpret_cast<const std::byte*>(seed), 32},
                std::span{reinterpret_cast<const std::byte*>(data), datalen},
                static_cast<attachment::Domain>(domain),
                std::span{reinterpret_cast<std::byte*>(out), attachment::encrypted_size(datalen)},
                /*allow_large=*/true);
        std::memcpy(key_out, key.data(), key.size());
        sodium_zero_buffer(key.data(), key.size());
        return true;
    } catch (const std::exception& e) {
        copy_c_str(error, 256, e.what());
        return false;
    }
}

LIBSESSION_C_API bool session_attachment_decrypt(
        const unsigned char* data,
        size_t datalen,
        const unsigned char* key,
        unsigned char* out,
        size_t* outlen,
        char* error) {

    try {
        auto max_size = attachment::decrypted_max_size(datalen);
        if (!max_size)
            throw std::runtime_error{"encrypted data too small"};

        *outlen = attachment::decrypt(
                std::span{reinterpret_cast<const std::byte*>(data), datalen},
                std::span<const std::byte, attachment::ENCRYPT_KEY_SIZE>{
                        reinterpret_cast<const std::byte*>(key), attachment::ENCRYPT_KEY_SIZE},
                std::span{reinterpret_cast<std::byte*>(out), *max_size});
        return true;
    } catch (const std::exception& e) {
        copy_c_str(error, 256, e.what());
        return false;
    }
}

LIBSESSION_C_API bool session_attachment_decrypt_alloc(
        const unsigned char* data,
        size_t datalen,
        const unsigned char* key,
        unsigned char** out,
        size_t* outlen,
        char* error) {
    std::byte* decrypted = nullptr;
    try {
        auto max_size = attachment::decrypted_max_size(datalen);
        if (!max_size)
            throw std::runtime_error{"encrypted data too small"};

        auto* decrypted = static_cast<std::byte*>(std::malloc(*max_size));
        *outlen = attachment::decrypt(
                std::span{reinterpret_cast<const std::byte*>(data), datalen},
                std::span<const std::byte, attachment::ENCRYPT_KEY_SIZE>{
                        reinterpret_cast<const std::byte*>(key), attachment::ENCRYPT_KEY_SIZE},
                std::span{decrypted, *max_size});
        *out = reinterpret_cast<unsigned char*>(decrypted);
        return true;
    } catch (const std::exception& e) {
        if (decrypted)
            std::free(decrypted);
        copy_c_str(error, 256, e.what());
        return false;
    }
}

LIBSESSION_C_API size_t session_attachment_encrypt_file(
        const unsigned char* seed,
        const char* filename,
        ATTACHMENT_DOMAIN domain,
        unsigned char* key_out,
        unsigned char* (*make_buffer)(size_t, void* ctx),
        void* ctx,
        char* error) {

    try {
        size_t enc_size = 0;
        auto key = attachment::encrypt(
                std::span{reinterpret_cast<const std::byte*>(seed), 32},
                std::filesystem::path{filename},
                static_cast<attachment::Domain>(domain),
                [make_buffer, ctx, &enc_size](size_t s) {
                    auto* buf = make_buffer(s, ctx);
                    if (!buf)
                        throw std::runtime_error{
                                "encryption failed: make_buffer function returned NULL"};
                    assert(!enc_size);
                    enc_size = s;
                    return std::span{reinterpret_cast<std::byte*>(buf), s};
                },
                /*allow_large=*/true);
        assert(enc_size);
        std::memcpy(key_out, key.data(), key.size());
        sodium_zero_buffer(key.data(), key.size());
        return enc_size;
    } catch (const std::exception& e) {
        copy_c_str(error, 256, e.what());
        return 0;
    }
}

LIBSESSION_C_API size_t session_attachment_decrypt_file(
        const char* file_in,
        const unsigned char* key,
        unsigned char* (*make_buffer)(size_t, void* ctx),
        void* ctx,
        char* error) {

    try {
        return attachment::decrypt(
                std::filesystem::path{file_in},
                std::span<const std::byte, attachment::ENCRYPT_KEY_SIZE>{
                        reinterpret_cast<const std::byte*>(key), attachment::ENCRYPT_KEY_SIZE},
                [make_buffer, ctx](size_t s) {
                    auto* buf = make_buffer(s, ctx);
                    if (!buf)
                        throw std::runtime_error{
                                "decryption failed: make_buffer function returned NULL"};
                    return std::span{reinterpret_cast<std::byte*>(buf), s};
                });
    } catch (const std::exception& e) {
        copy_c_str(error, 256, e.what());
        return std::numeric_limits<size_t>::max();
    }
}

LIBSESSION_C_API bool session_attachment_decrypt_to_file(
        const unsigned char* data,
        size_t datalen,
        const unsigned char* key,
        const char* file_out,
        char* error) {

    try {
        attachment::decrypt(
                std::span{reinterpret_cast<const std::byte*>(data), datalen},
                std::span<const std::byte, attachment::ENCRYPT_KEY_SIZE>{
                        reinterpret_cast<const std::byte*>(key), attachment::ENCRYPT_KEY_SIZE},
                std::filesystem::path{file_out});
        return true;
    } catch (const std::exception& e) {
        copy_c_str(error, 256, e.what());
        return false;
    }
}

LIBSESSION_C_API bool session_attachment_decrypt_file_to_file(
        const char* file_in, const unsigned char* key, const char* file_out, char* error) {

    try {
        attachment::decrypt(
                std::filesystem::path{file_in},
                std::span<const std::byte, attachment::ENCRYPT_KEY_SIZE>{
                        reinterpret_cast<const std::byte*>(key), attachment::ENCRYPT_KEY_SIZE},
                std::filesystem::path{file_out});
        return true;
    } catch (const std::exception& e) {
        copy_c_str(error, 256, e.what());
        return false;
    }
}
}
