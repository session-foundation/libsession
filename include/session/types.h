#pragma once

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define OPTIONAL
#if defined(_MSC_VER)
#define NON_NULL_ARG(...)
#else
#define NON_NULL_ARG(...) __attribute__((nonnull(__VA_ARGS__)))
#endif

/// C friendly buffer structure that is a pointer and length to a span of bytes.
typedef struct span_u8 span_u8;
struct span_u8 {
    uint8_t* data;
    size_t size;
};

typedef struct bytes32 bytes32;
struct bytes32 {
    uint8_t data[32];
};

typedef struct bytes33 bytes33;
struct bytes33 {
    uint8_t data[33];
};

typedef struct bytes64 bytes64;
struct bytes64 {
    uint8_t data[64];
};

/// A wrapper around snprintf that fixes a common bug in the value the printing function returns
/// when a buffer is passed in. Irrespective of whether a buffer is passed in, snprintf is defined
/// to return:
///
///  number of characters (not including the terminating null character) which would have been
///  written to buffer if bufsz was ignored
///
/// This means if the user passes in a buffer to small, the return value is always the amount of
/// bytes required. This means the user always has to calculate the number of bytes written as:
///
///   size_t bytes_written = min(snprintf(buffer, size, ...), size);
///
/// This is error prone. This function does the `min(...)` for you so that this function
/// _always_ calculates the actual number of bytes written (not including the null-terminator). If a
/// NULL is passed in then this function returns the number of bytes actually needed to write the
/// entire string (as per normal snprintf behaviour).
int snprintf_clamped(char* buffer, size_t size, char const* fmt, ...);

#ifdef __cplusplus
}
#endif
