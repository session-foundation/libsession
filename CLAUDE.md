# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Build Commands

```bash
# Configure (out-of-source build required)
cmake -G Ninja -S . -B build-claude

# Build
cmake --build build-claude --parallel --verbose

# Run tests
./build-claude/tests/testAll [test-tag-or-name]

# Regenerate protobuf files
cmake --build build-claude --target regen-protobuf --parallel
```

### Notable CMake Options

- `-DBUILD_STATIC_DEPS=ON` — force all deps to build statically (no system libs)
- `-DENABLE_ONIONREQ=ON/OFF` — include onion request / network functionality (default ON)
- `-DWARNINGS_AS_ERRORS=ON` — treat warnings as errors
- `-DSUBMODULE_CHECK=OFF` — skip submodule freshness checks (useful during dev)
- `-DWITH_IP_GEOLOCATION=ON` — bundle the DB-IP IP-to-country database, +1.79MB (default OFF, in
  which case `session::ip_country` lookups all report unknown).  Requires running
  `utils/update-ip-country-db.py` first: the generated table is not committed, and cmake fails with
  instructions if it is missing.

## Architecture Overview

This is **libsession-util**, the C++20 utility library for Session clients. It provides:

1. **Cryptographic primitives** (`libsession::crypto`) — Ed25519/X25519 keys, blinding, hashing, encryption (session protocol, multi-encrypt, attachments), XEd25519 signatures.

2. **Config sync system** (`libsession::config`) — CRDT-style distributed config that syncs across Session devices via swarm storage. Each config type has a namespace:
   - `UserProfile`, `Contacts`, `ConvoInfoVolatile`, `UserGroups` — per-user configs
   - `GroupKeys`, `GroupInfo`, `GroupMembers` — shared group configs (closed groups)
   - `Local` — device-local config (never pushed to swarm)
   - Config messages use bt-encoding (bencode), seqno-based CRDT merge with deterministic tie-breaking. See `docs/api/docs/config_merge_logic.md` for protocol details.

3. **Core** (`libsession::core`) — Persistent client state backed by SQLite. The `Core` class owns `CoreComponent`-derived members (`Globals`, `Devices`, `Pro`) that share a connection pool. Migrations live in `src/core/schema/` as `NNN_name.sql` or `NNN_name.cpp` files.

4. **Onion requests** (`libsession::onionreq`, optional) — Builder/parser for onion-routed requests to the Session network.

### Library Targets and Dependencies

```
util     ← file, logging, util (uses zstd, simdutf)
crypto   ← util + libsodium (blinding, ed25519, session_encrypt, etc.)
config   ← crypto + libsodium + protos (all config types)
core     ← crypto + SQLite + mlkem768 (PQC key encapsulation)
image    ← util + libvips (image processing)
onionreq ← crypto + quic + nettle (optional)
```

All targets are aliased as `libsession::util`, `libsession::crypto`, etc.

### Header Layout

Public headers are in `include/session/`:
- `include/session/config/` — config type headers (`.h` = C API, `.hpp` = C++ API)
- `include/session/config/groups/` — closed group configs (keys, info, members)
- `include/session/core/` — Core persistent state components
- `include/session/image/` — image processing (libvips setup and its loader whitelist)
- `include/session/onionreq/` — onion request types

### Dependency System

Dependencies are managed via `cmake/session-deps/` which provides `session_dep()` and `sessiondep_or_submodule()` macros. These first try system libraries; if not found they fall back to static builds. External submodules live in `external/` (ios-cmake, protobuf, session-router, session-sqlite, date). oxen-libquic, oxen-logging, oxenc and nlohmann-json are not submodules here: they are taken from the nested copies under `external/session-router/external/`.

### Tests

Tests use Catch2. Most tests are compiled into `testAll`; logging tests are isolated in `testLogging` because they modify global sink/level state. Filter tests with Catch2 tag syntax, e.g. `./Build/tests/testAll "[config]"`.

### Dual C/C++ API

Many headers come in pairs: `foo.h` (C API for FFI use) and `foo.hpp` (C++ API).  The C API generally is a wrapper around the primary C++ API.  When adding new public functionality, consider whether a C API is needed.

## Code Style

- **Format with `./utils/format.sh` before every commit**, and check it with `./utils/format.sh verify`
  (exit 0 means clean).  Do not run `clang-format` yourself: the script pins **clang-format-19** and
  formats the whole source list, and other versions — including whatever `clang-format` points at —
  produce different output that fails CI.
- **Prefer DRY code**: when logic is duplicated across two or more call sites, extract a shared helper.  Do this proactively when writing new code, not only when asked.
- **Specify the shape upfront**: when asked to implement something that overlaps with existing code, identify and extract the shared piece before writing the new code, so duplication never appears in the first place.
