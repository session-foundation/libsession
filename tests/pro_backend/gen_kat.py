#!/usr/bin/env python3
"""Generate the known-answer vectors asserted by the [pro_kat] test in tests/test_pro_backend.cpp.

These pin libsession's signed-message construction (wire spec §1.1 / §2 / §3). The
vectors are produced here from the *backend's* independent implementation (backend.signed_message +
the make_*_message / build_proof_message builders) for fixed, deterministic inputs, then hand-verified
against the spec field layout before being frozen into the C++ test. Re-run this if the signed-message
format ever changes (it is a deliberate, both-sides wire change) and update the constants + the
hand-verification in the test to match.

Run with the backend clone's venv python; requires env:
  PRO_BACKEND_DIR   path to the backend checkout (for importing backend/base)

  PRO_BACKEND_DIR=~/src/session-pro-backend .venv/bin/python gen_kat.py
"""
import datetime
import os
import sys

sys.path.insert(0, os.environ["PRO_BACKEND_DIR"])

import nacl.signing  # noqa: E402

import backend  # noqa: E402
import base  # noqa: E402


def hx(b):
    return bytes(b).hex()


def main():
    # Fixed deterministic keypairs from 32-byte seeds (backend signing key 0x03).
    master = nacl.signing.SigningKey(bytes([1] * 32))
    rotating = nacl.signing.SigningKey(bytes([2] * 32))
    backkey = nacl.signing.SigningKey(bytes([3] * 32))
    mpk, rpk = master.verify_key, rotating.verify_key

    ts = datetime.datetime.fromtimestamp(1700000000, datetime.timezone.utc)
    expiry = datetime.datetime.fromtimestamp(1704067200, datetime.timezone.utc)
    limit = 10
    before_cursor = "0a1b2c3d4e5f"  # opaque to the signed input; any fixed non-empty string works
    provider = base.PaymentProvider.GooglePlayStore
    pid = "test-payment-id-123"
    rtag = bytes([0x11] * 32)

    add_msg = backend.signed_message(
        backend.ADD_PRO_PAYMENT_DOMAIN, mpk, rpk, provider.value, pid)
    gen_msg = backend.make_generate_pro_proof_message(mpk, rpk, ts)
    # get_pro_details read request is split (§3.4) into get_pro_status + paginated get_payment_details.
    status_msg = backend.make_get_pro_status_message(mpk, ts)
    # Two payment_details cases: empty `before` (newest page) ends in the adjacency `\0`;
    # a non-empty `before` appends the opaque cursor verbatim as the final field (no trailing sep).
    details_empty_msg = backend.make_get_payment_details_message(mpk, ts, limit, "")
    details_cursor_msg = backend.make_get_payment_details_message(mpk, ts, limit, before_cursor)
    prf_msg = backend.build_proof_message(rtag, rpk, expiry)

    print("master_pkey  =", hx(mpk.encode()))
    print("rotating_pkey=", hx(rpk.encode()))
    print("backend_pkey =", hx(backkey.verify_key.encode()))
    print()
    for name, m in [("add", add_msg), ("gen", gen_msg), ("status", status_msg),
                    ("details_empty", details_empty_msg), ("details_cursor", details_cursor_msg),
                    ("proof", prf_msg)]:
        print(f"{name}_msg_hex = {hx(m)}")
        print(f"    repr     = {m!r}")
    print()
    print("add_master_sig =", hx(master.sign(add_msg).signature))
    print("add_rotating_sig =", hx(rotating.sign(add_msg).signature))
    print("proof_sig =", hx(backkey.sign(prf_msg).signature))


if __name__ == "__main__":
    main()
