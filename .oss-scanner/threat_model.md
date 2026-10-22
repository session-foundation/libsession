# libsession-util threat model

## What this project does

libsession-util is the C++20 core of the Session messenger's clients (iOS, Android, Desktop, and
the Session 2.0 app). It implements the Session protocol: message encryption and decryption,
encrypted config sync between a user's devices, closed groups, the linked-device group and its
account keys (perfect forward secrecy and post-quantum encryption for one-to-one messages), onion
requests through Session service nodes, file and community server clients, image handling for
attachments, and the persistent client state (SQLite) behind the `core` and `client` layers.
Clients use it through a C++ API and a paired C API (`include/session/**/*.h`) for FFI.

Session's promise to users is that message content, contact lists and account data are readable
only by the user's own devices and the intended recipients, and that the network learns as little
metadata as possible. A bug matters in proportion to how much of that promise it breaks.

## Where untrusted input enters

Treat every byte that arrives from outside the local device as attacker-controlled. In particular:

- **Messages from other users** — one-to-one, closed-group and community messages: the poll and
  push handling in `src/core.cpp` (`Core::_handle_poll_response`, `_handle_server_push`),
  `session_protocol` (`decode_dm_envelope`, `decode_group_envelope`, `decode_for_community`; the v1
  envelope and the v2 PFS message with ML-KEM), `session_encrypt`, `multi_encrypt`, protobuf
  `Content` (`proto/`), and `src/client/client.cpp`, which turns decoded messages into stored rows
  (attachment URL, key and size, replies, reactions, deletions).
- **Contacts' published account keys** (PFS) — `Core::_handle_pfs_response` and `_store_pfs_keys`:
  signature checks, binding to the Session ID, and anything that substitutes or downgrades a
  contact's keys.
- **Config messages from the user's other devices, and from other members of a closed group** —
  `config::*` merge and `config/encrypt.cpp` (`decrypt_inplace`), bt-encoded dicts merged by
  `bt_merge`, and group keys/info/members (`src/config/groups/`). Any member of a group can push.
- **Device-group messages and link requests** (Session 2.0, namespace 21) —
  `core::Devices::receive_device_group_message`, `receive_link_request`, `parse_device_messages`,
  `parse_account_pubkeys` in `src/core/devices.cpp`, and the link SAS (`src/core/link_sas.cpp`).
  The design is in `docs/protocol-v2.md` and, for how applications use it, `docs/device-groups.md`.
- **Swarm and service-node responses** — storage-server retrieve results (message bodies *and* their
  metadata: hashes, timestamps and expiries are reported by the node and are not signed), the
  service-node list (`process_snode_cache_bin` and `from_json` in `src/network/service_node.cpp`),
  swarm and 421 swarm-change lists, the snode pool (`src/network/snode_pool.cpp`: a malicious node
  poisoning the pool, path and subnet diversity), and onion-request responses
  (`src/onionreq/response_parser.cpp`, `src/network/routing/`).
- **File server, community (SOGS) server and Pro backend responses** — `src/network/backends/`,
  `pro_backend.cpp` (`parse_pro_proof`, `parse_pro_status`, `parse_revocations`, ...) and the Pro
  signature checks in `src/core/pro.cpp`.
- **Attachments and images** — attacker-supplied ciphertext and stream-encrypted attachments
  (`attachments.cpp`, including the URL-fragment format flags and size handling), the download
  cache (`src/client/download_cache.cpp`), and sender-supplied images in `src/image/`: header
  probing and pixel limits (`probe.cpp`), image sources including encrypted files (`source.cpp`),
  decoding through libvips and libheif behind a loader whitelist (`vips.cpp`), JPEG encoding, and
  thumbhash. An image that reaches a loader outside the whitelist, or is decoded past the pixel
  limits, is a finding.
- **Strings a user is given by someone else** — community URLs (`config::community::parse_*`),
  Session IDs and conversation IDs (`client::ConversationId::parse`), and recovery phrases
  (`src/mnemonics/`).

## Adversaries

In scope:

- **Any other Session user**, including members of a group the victim is in.
- **A malicious service node**, including one in the victim's swarm or on an onion path. It can
  drop, delay, replay, reorder and re-date stored messages, and return arbitrary responses, but it
  cannot sign as a user. Anything it achieves that the design reserves for a seed holder (below),
  such as displacing a device by re-dating messages, is a finding.
- **A malicious file, community or Pro server**, or anything able to answer in its place.
- **A holder of the account's seed, a removed device included.** The design lets a seed holder act
  as the account and does not try to prevent it (`docs/protocol-v2.md`, "Removed devices" and
  "Displaced devices"): it can publish account keys of its own, delete the account's messages,
  register a device in the device group, displace its members or dissolve it. Those that reach the
  device group are announced to every member's user instead. So the findings here are:
  - a device added, a member displaced or a group dissolved without the user being told;
  - anything a removed device can still read after the members' device keys have rotated;
  - a *passive* seed holder, one who reads stored messages but does not act, decrypting one-to-one
    messages: past, present or future, the PFS goal stated at the top of `docs/protocol-v2.md`;
  - joining a device group through a link request without the user seeing an SAS mismatch.
- **A passive network observer or storage-server operator** logging everything for later
  decryption.

Out of scope:

- A fully compromised local device or process: an attacker who can read the app's memory, its
  SQLite database or its key storage, or call the library directly. (Key material leaking *out* of
  the protected places, into logs, temporary files or unlocked memory, is in scope.)
- SQL injection through session-sqlite: every query is prepared. What the library itself wrote to
  its database is trusted when read back; what it stores from the network is not.
- Everything else the design lets a seed holder do (see above), such as receiving a contact's future
  messages by publishing account keys of its own. Holding the seed *is* holding the account.
- Denial of service that the protocol cannot prevent: a swarm withholding all messages, a server
  refusing to answer, flooding with valid traffic.

## Components that matter most / least

Most:
- Decryption, signature verification and decoding of anything received: `session_encrypt`,
  `session_protocol`, `multi_encrypt`, `config/encrypt.cpp`, `onionreq/`, `attachments.cpp`.
- The Session 2.0 code in `src/core/` (device groups, account keys, link requests) and
  `src/client/`. It is new, and its trust rules are the least exercised.
- Image handling in `src/image/`, since every image a contact sends passes through it.
- Config merge and closed-group keys (`src/config/`), since a poisoned config is stored and
  re-processed on every start.

Least:
- `tests/`, `utils/`, `docs/`: test drivers, build scripts and documentation. A defect in test code
  (a test that leaks the C API objects it creates, or misuses a temporary) is not a finding; the
  same defect in `src/` on a path reachable from untrusted input is.
- `external/` and the libraries the build links (protobuf, session-router, oxen-libquic,
  session-sqlite, libvips, libheif, ...): report a bug there to its own project. It is in scope here
  only when the defect is in how libsession-util uses it.
- iOS, Android and macOS build tooling.

## How to exercise it

- The image is built in `/src/build`: Debian trixie, gcc, a Debug build (libsession's threading and
  state checks are asserts), shared libraries, system dependencies. `cmake --build /src/build`
  rebuilds after a change.
- `/src/build-asan` is the same build with AddressSanitizer and UndefinedBehaviorSanitizer, linked
  statically, ready to use. Rebuild it after a change with `cmake --build /src/build-asan -j2`: keep `-j` small, because
  `nproc` reports the host's cores rather than the container's share and sanitized C++ compiles need
  over 1 GB each.
- `tests/testAll`, in either build, is the Catch2 suite (about 460 cases, a minute or so); filter by
  tag or name, for example `testAll "[config]"`. The network layer is mocked, so it needs no network.
  `testLogging` is separate because it changes global logging state. The `[pro_live]` cases, which
  need a running Pro backend, are compiled out of this build. The live-network tests
  (`BUILD_LIVE_TESTS`) are not built: they need the real Session network.
- A further build directory also configures offline. The dependency tarballs it would download are
  kept in `/opt/session-deps-sources`: copy them into `<builddir>/static-deps-sources/src/` before
  running cmake.
- `/opt/context/` holds shallow checkouts of the servers libsession talks to: the storage server,
  file server, community server (SOGS) and Pro backend. They show what responses can contain. They
  are not built, may differ from what is deployed, and are not part of this scan.
- New reproducers fit best as a Catch2 `TEST_CASE` in the matching `tests/test_*.cpp`. The
  existing tests show how to build valid messages, configs and keys to mutate from.

## How we rate severity

Rate by what an in-scope adversary achieves, not by bug class alone.

- **Critical**
  - Code execution, or a memory-corruption bug with a credible path to it, reachable remotely
    without user interaction (a received message, config, image, swarm or server response).
  - Disclosure of message plaintext, or of private key material (root seed, device keys, account
    keys, group keys), to a party not entitled to it.
  - Forging a message, config, device-group message or link request that the victim accepts as
    authentic from someone else; joining a closed group or device group without being admitted.
  - Breaking the PFS guarantee: a passive holder of the seed, or someone who logged stored messages
    and later obtains it, can decrypt one-to-one messages, past, present or future.
- **High**
  - Memory-safety bugs (out-of-bounds read or write, use-after-free, double free, uninitialised
    read) reachable from untrusted input, without a demonstrated exploit.
  - Changing device-group or closed-group membership or keys without the seed or the rights the
    design requires; a seed holder doing so without the user being told; a removed device reading
    content after the device keys have rotated.
  - Persistent denial of service: input that crashes or wedges the client on every start (a stored
    config or database state), or permanently breaks a conversation, group or device link.
- **Medium**
  - Transient remote denial of service: a crash, hang or excessive memory or CPU use that a restart
    clears, including an image that decodes past the pixel limits.
  - Metadata disclosure beyond what the protocol documents: who a user talks to, group or device
    membership, IP address leaks around onion routing.
  - State a malicious service node can corrupt by replaying or re-dating messages, when the client
    recovers on its own.
- **Low**
  - Bugs reachable only through the local API with arguments no client passes, or only by a
    local attacker; undefined behaviour with no observable effect; leaks of non-secret data to
    logs; hardening gaps with no demonstrated impact.

## How we would like reports

- A reproducer that runs in this image, ideally as a Catch2 test that fails before the fix and
  passes after it. Say which adversary from the list above can deliver the input.
- A minimal patch in the style of the surrounding code (the project formats with clang-format 19
  via `./utils/format.sh`; it is not installed in this image). When a C++ API changes, update the
  paired C API in `include/session/**/*.h` too.
- For protocol-level findings, cite the section of `docs/protocol-v2.md` the behaviour contradicts.
