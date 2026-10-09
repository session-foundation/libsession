#include "session/attachments.hpp"

#include <session/attachments.h>
#include <sodium/crypto_core_hchacha20.h>
#include <sodium/crypto_generichash_blake2b.h>
#include <sodium/crypto_secretstream_xchacha20poly1305.h>

#include <concepts>
#include <cstring>
#include <fstream>
#include <functional>
#include <limits>
#include <oxen/log.hpp>
#include <oxen/log/format.hpp>
#include <session/util.hpp>
#include <stdexcept>
#include <type_traits>

#include "internal-util.hpp"

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
        std::span<unsigned char, ENCRYPT_HEADER> header,
        std::span<const unsigned char, ENCRYPT_KEY_SIZE> key,
        std::span<const unsigned char, ENCRYPT_HEADER> nonce) {

    crypto_secretstream_xchacha20poly1305_state st;

    std::memcpy(header.data(), nonce.data(), ENCRYPT_HEADER);
    crypto_core_hchacha20(
            st.k, header.data(), reinterpret_cast<const unsigned char*>(key.data()), nullptr);
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

// Encryption implementation function.  `get_chunk(N)` returns a pair of [span<const unordered
// char>, bool] of the next N (max ENCRYPT_CHUNK_SIZE) bytes, less than N only at the end of the
// input, where the bool is true if there is at least 1 byte more of data to be retrieved (i.e.
// false means the end of the data).  It may not return an empty chunk except for the very first
// call.
template <std::invocable<size_t> ReadData>
static void encrypt_impl(
        std::span<std::byte> out,
        size_t data_size,
        std::span<const unsigned char, ENCRYPT_HEADER + ENCRYPT_KEY_SIZE> nonce_key,
        ReadData get_chunk) {
    size_t padding = encrypted_padding(data_size);
    assert(padding >= 1);
    size_t padded_size = data_size + padding;

    assert(out.size() == encrypted_size(data_size));
    out[0] = std::byte{'S'};

    std::span<unsigned char> uout{reinterpret_cast<unsigned char*>(out.data()), out.size()};

    std::span<unsigned char, ENCRYPT_HEADER> header{uout.data() + 1, ENCRYPT_HEADER};

    auto st = secretstream_xchacha20poly1305_init_push_with_nonce(
            header, nonce_key.last<ENCRYPT_KEY_SIZE>(), nonce_key.first<ENCRYPT_HEADER>());

    auto* outpos = uout.data() + 1 + ENCRYPT_HEADER;
    auto* const outend = uout.data() + uout.size();

    // Now we build a buffer containing padding, plus whatever initial actual data goes on the end
    // of the last chunk of padding:
    bool done = false;
    {
        std::vector<unsigned char> buf;
        buf.reserve(std::min(ENCRYPT_CHUNK_SIZE, padded_size));
        for (size_t padding_remaining = padding; padding_remaining;) {
            unsigned char tag = 0;
            if (padding_remaining > ENCRYPT_CHUNK_SIZE) {
                // Full chunk of 0x00 padding (with more padding in the next chunk)
                buf.resize(ENCRYPT_CHUNK_SIZE);
                padding_remaining -= ENCRYPT_CHUNK_SIZE;
            } else {
                buf.resize(padding_remaining - 1);  // 0x00 padding
                buf.push_back(0x01);                // padding terminator
                auto [chunk, more] = get_chunk(ENCRYPT_CHUNK_SIZE - padding_remaining);
                assert(chunk.size() == ENCRYPT_CHUNK_SIZE - padding_remaining || !more);
                if (!chunk.empty())
                    buf.insert(buf.end(), chunk.begin(), chunk.end());
                padding_remaining = 0;
                if (!more) {
                    tag = crypto_secretstream_xchacha20poly1305_TAG_FINAL;
                    done = true;
                }
            }

            assert(outpos + buf.size() + crypto_secretstream_xchacha20poly1305_ABYTES <= outend);

            unsigned long long out_len;
            crypto_secretstream_xchacha20poly1305_push(
                    &st, outpos, &out_len, buf.data(), buf.size(), nullptr, 0, tag);
            assert(out_len == buf.size() + crypto_secretstream_xchacha20poly1305_ABYTES);
            outpos += out_len;
        }
    }

    // Now we're through the initial padding (and probably some initial data): now all we need to do
    // is push the rest of the data

    while (!done) {
        auto [chunk, more] = get_chunk(ENCRYPT_CHUNK_SIZE);
        assert(!chunk.empty());
        assert(chunk.size() == ENCRYPT_CHUNK_SIZE || !more);
        assert(outpos + chunk.size() + crypto_secretstream_xchacha20poly1305_ABYTES <= outend);

        unsigned char tag = more ? 0 : crypto_secretstream_xchacha20poly1305_TAG_FINAL;

        unsigned long long out_len;
        crypto_secretstream_xchacha20poly1305_push(
                &st, outpos, &out_len, chunk.data(), chunk.size(), nullptr, 0, tag);
        assert(out_len == chunk.size() + crypto_secretstream_xchacha20poly1305_ABYTES);
        outpos += out_len;
        if (!more)
            done = true;
    }
}

static std::tuple<
        std::array<unsigned char, ENCRYPT_HEADER + ENCRYPT_KEY_SIZE>,
        std::array<std::byte, ENCRYPT_KEY_SIZE>,
        const unsigned char*,
        const unsigned char*>
encrypt_buffer_init(
        std::span<const std::byte> seed,
        std::span<const std::byte> data,
        Domain domain,
        bool allow_large) {
    std::tuple<
            std::array<unsigned char, ENCRYPT_HEADER + ENCRYPT_KEY_SIZE>,
            std::array<std::byte, ENCRYPT_KEY_SIZE>,
            const unsigned char*,
            const unsigned char*>
            result;
    auto& [nonce_key, key, inpos, inend] = result;

    if (seed.size() < 32)
        throw std::invalid_argument{"attachment::encrypt requires a 32-byte uploader seed"};

    if (data.size() > MAX_REGULAR_SIZE && !allow_large)
        throw std::invalid_argument{"data to encrypt is too large"};

    std::span<const unsigned char> udata{
            reinterpret_cast<const unsigned char*>(data.data()), data.size()};

    crypto_generichash_blake2b_state b_st;
    const auto domain_byte = static_cast<uint8_t>(domain);
    crypto_generichash_blake2b_init(&b_st, &domain_byte, 1, nonce_key.size());
    crypto_generichash_blake2b_update(
            &b_st, reinterpret_cast<const unsigned char*>(seed.data()), 32);
    crypto_generichash_blake2b_update(&b_st, udata.data(), udata.size());
    crypto_generichash_blake2b_final(&b_st, nonce_key.data(), nonce_key.size());
    std::memcpy(key.data(), nonce_key.data() + ENCRYPT_HEADER, ENCRYPT_KEY_SIZE);

    inpos = udata.data();
    inend = inpos + udata.size();

    return result;
}

std::array<std::byte, ENCRYPT_KEY_SIZE> encrypt(
        std::span<const std::byte> seed,
        std::span<const std::byte> data,
        Domain domain,
        std::span<std::byte> out,
        bool allow_large) {

    auto [nonce_key, key, inpos, inend] = encrypt_buffer_init(seed, data, domain, allow_large);

    encrypt_impl(
            out,
            data.size(),
            nonce_key,
            [&inpos, &inend](size_t size) -> std::pair<std::span<const unsigned char>, bool> {
                auto* start = inpos;
                auto* end = std::min(inpos + size, inend);
                inpos = end;
                return {{start, end}, inpos != inend};
            });

    return key;
}

std::pair<std::vector<std::byte>, std::array<std::byte, ENCRYPT_KEY_SIZE>> encrypt(
        std::span<const std::byte> seed,
        std::span<const std::byte> data,
        Domain domain,
        bool allow_large) {

    if (seed.size() < 32)
        throw std::invalid_argument{"attachment::encrypt requires a 32-byte uploader seed"};

    if (data.size() > MAX_REGULAR_SIZE && !allow_large)
        throw std::invalid_argument{"data to encrypt is too large"};

    std::pair<std::vector<std::byte>, std::array<std::byte, ENCRYPT_KEY_SIZE>> result;
    auto& [out, key] = result;

    out.resize(encrypted_size(data.size()));

    key = encrypt(seed, data, domain, out, allow_large);

    return result;
}

std::array<std::byte, ENCRYPT_KEY_SIZE> encrypt(
        std::span<const std::byte> seed,
        const std::filesystem::path& file,
        Domain domain,
        std::function<std::span<std::byte>(size_t enc_size)> make_buffer,
        bool allow_large) {

    if (seed.size() < 32)
        throw std::invalid_argument{"attachment::encrypt requires a 32-byte uploader seed"};

    std::ifstream in;
    in.exceptions(std::ios::badbit);
    in.open(file, std::ios::binary | std::ios::ate);
    size_t size = in.tellg();
    in.seekg(0, std::ios::beg);

    if (size > MAX_REGULAR_SIZE && !allow_large)
        throw std::invalid_argument{"data to encrypt is too large"};

    size = encrypted_size(size);

    std::array<unsigned char, ENCRYPT_HEADER + ENCRYPT_KEY_SIZE> nonce_key;

    crypto_generichash_blake2b_state b_st;
    const auto domain_byte = static_cast<uint8_t>(domain);
    crypto_generichash_blake2b_init(&b_st, &domain_byte, 1, nonce_key.size());
    crypto_generichash_blake2b_update(
            &b_st, reinterpret_cast<const unsigned char*>(seed.data()), 32);

    size_t in_size = 0;
    std::array<std::byte, 4096> chunk;
    while (in.read(reinterpret_cast<char*>(chunk.data()), chunk.size())) {
        crypto_generichash_blake2b_update(
                &b_st, reinterpret_cast<const unsigned char*>(chunk.data()), chunk.size());
        in_size += chunk.size();
    }
    if (in.gcount() > 0) {
        crypto_generichash_blake2b_update(
                &b_st, reinterpret_cast<const unsigned char*>(chunk.data()), in.gcount());
        in_size += in.gcount();
    }

    crypto_generichash_blake2b_final(&b_st, nonce_key.data(), nonce_key.size());

    std::array<std::byte, ENCRYPT_KEY_SIZE> key;
    std::memcpy(key.data(), nonce_key.data() + ENCRYPT_HEADER, ENCRYPT_KEY_SIZE);

    in.clear();
    in.exceptions(std::ios::badbit | std::ios::failbit);
    in.seekg(0, std::ios::beg);

    auto encrypted = make_buffer(size);
    if (encrypted.size() != size)
        throw std::logic_error{
                "make_buffer returned span of invalid size: expected {}, got {}"_format(
                        size, encrypted.size())};

    std::array<unsigned char, ENCRYPT_CHUNK_SIZE> buf;
    encrypt_impl(
            encrypted,
            in_size,
            nonce_key,
            [&in, &in_size, &buf](size_t size) -> std::pair<std::span<const unsigned char>, bool> {
                size_t consumed = in.tellg();
                if (consumed + size > in_size)
                    size = in_size - consumed;

                if (size > 0)
                    in.read(reinterpret_cast<char*>(buf.data()), size);

                in.peek();
                return {std::span{buf}.first(size), !in.eof()};
            });

    return key;
}

std::pair<std::vector<std::byte>, std::array<std::byte, ENCRYPT_KEY_SIZE>> encrypt(
        std::span<const std::byte> seed,
        const std::filesystem::path& file,
        Domain domain,
        bool allow_large) {

    std::pair<std::vector<std::byte>, std::array<std::byte, ENCRYPT_KEY_SIZE>> result;
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

std::array<std::byte, ENCRYPT_KEY_SIZE> encrypt(
        std::span<const std::byte> seed,
        std::span<const std::byte> data,
        Domain domain,
        const std::filesystem::path& file,
        bool allow_large) {

    auto [nonce_key, key, inpos, inend] = encrypt_buffer_init(seed, data, domain, allow_large);

    size_t padding = encrypted_padding(data.size());
    assert(padding >= 1);
    size_t padded_size = data.size() + padding;

    try {
        std::ofstream out;
        out.exceptions(std::ios::failbit | std::ios::badbit);
        out.open(file, std::ios::binary | std::ios::trunc);
        out.write("S", 1);

        std::array<char, ENCRYPTED_CHUNK_TOTAL> cbuf;
        std::span ubuf{reinterpret_cast<unsigned char*>(cbuf.data()), cbuf.size()};

        auto st = secretstream_xchacha20poly1305_init_push_with_nonce(
                ubuf.first<ENCRYPT_HEADER>(),
                std::span{nonce_key}.last<ENCRYPT_KEY_SIZE>(),
                std::span{nonce_key}.first<ENCRYPT_HEADER>());

        out.write(cbuf.data(), ENCRYPT_HEADER);

        // Now we build a buffer containing padding, plus whatever initial actual data goes on the
        // end of the last chunk of padding, and write those encrypted padding chunks to the file:
        {
            std::vector<unsigned char> buf;
            buf.reserve(std::min(ENCRYPT_CHUNK_SIZE, padded_size));
            for (size_t padding_remaining = padding; padding_remaining;) {
                if (padding_remaining > ENCRYPT_CHUNK_SIZE) {
                    // Full chunk of 0x00 padding (with more padding in the next chunk)
                    buf.resize(ENCRYPT_CHUNK_SIZE);
                    padding_remaining -= ENCRYPT_CHUNK_SIZE;
                } else {
                    buf.resize(padding_remaining - 1);  // 0x00 padding
                    buf.push_back(0x01);                // padding terminator
                    if (size_t first_data =
                                std::min(ENCRYPT_CHUNK_SIZE - padding_remaining, data.size())) {
                        buf.insert(buf.end(), inpos, inpos + first_data);
                        inpos += first_data;
                    }
                    padding_remaining = 0;
                }

                unsigned char tag =
                        inpos < inend ? 0 : crypto_secretstream_xchacha20poly1305_TAG_FINAL;

                unsigned long long out_len;
                crypto_secretstream_xchacha20poly1305_push(
                        &st, ubuf.data(), &out_len, buf.data(), buf.size(), nullptr, 0, tag);
                assert(out_len == buf.size() + crypto_secretstream_xchacha20poly1305_ABYTES);
                out.write(cbuf.data(), out_len);
            }
        }

        // Now we're through the initial padding (and probably some initial data): now all we need
        // to do is write the rest of the data in chunks
        while (inpos < inend) {
            auto* chunk_start = inpos;
            inpos = std::min(chunk_start + ENCRYPT_CHUNK_SIZE, inend);
            unsigned char tag = inpos < inend ? 0 : crypto_secretstream_xchacha20poly1305_TAG_FINAL;

            unsigned long long out_len;
            crypto_secretstream_xchacha20poly1305_push(
                    &st, ubuf.data(), &out_len, chunk_start, inpos - chunk_start, nullptr, 0, tag);
            assert(out_len == inpos - chunk_start + crypto_secretstream_xchacha20poly1305_ABYTES);

            out.write(cbuf.data(), out_len);
        }
    } catch (const std::exception& e) {
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

    std::span<const unsigned char> uenc{
            reinterpret_cast<const unsigned char*>(encrypted.data()), encrypted.size()};

    crypto_secretstream_xchacha20poly1305_state st;
    crypto_secretstream_xchacha20poly1305_init_pull(
            &st, uenc.data() + 1, reinterpret_cast<const unsigned char*>(key.data()));

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
                        inpos,
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
                    inpos,
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
        if (padend != out.end()) {
            if (*padend != std::byte{0x01}) {
                failed = true;
                return;
            }
            depadded = true;
            if (++padend != out.end())
                output(std::span<const std::byte>{padend, out.end()});
        }
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
        return set_error(error, e);
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
        return set_error(error, e);
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
        return set_error(error, e);
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
        set_error(error, e);
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
        set_error(error, e);
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
        return set_error(error, e);
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
        return set_error(error, e);
    }
}
}
