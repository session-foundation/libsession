#!/usr/bin/env python3
"""Seed backend DB state for the libsession [pro_live] integration tests.

Injects the "as if a provider purchase notification was witnessed" state straight into postgres, so
a subsequent *real* add_pro_payment from the client redeems it -- no dev-mode, no fake provider
egress (provider_dry_run stubs the egress; this just supplies the witnessed row the egress would
otherwise have created). This mirrors what the backend's own test.py does in-process
(test_provider_dry_run_redeems_google_without_egress / test_server_add_payment_flow), except we run
out-of-process against the same DB.

Run with the backend clone's venv python. Requires env:
  SESH_PRO_BACKEND_DB_URL   postgres DSN (same one the backend uses)
  PRO_BACKEND_DIR           path to the backend clone (for importing base/backend/db)

Usage:
  seed_payment.py payment --provider {google_play,app_store,stf} --payment-id ID
                          --master-pubkey HEX64 [--plan 1m|3m|1y] [--expiry-days N]
  seed_payment.py revoke  --provider {google_play,app_store} --payment-id ID
"""
import argparse
import datetime
import os
import sys

sys.path.insert(0, os.environ["PRO_BACKEND_DIR"])

import nacl.signing  # noqa: E402

import backend  # noqa: E402
import base  # noqa: E402
import db  # noqa: E402


def _open():
    err = base.ErrorSink()
    url = os.environ["SESH_PRO_BACKEND_DB_URL"]
    # bootstrap_db no longer takes/uses an ErrorSink (it raises on failure); the err sink is still
    # used by the add_unredeemed_payment / add_*_revocation calls below.
    engine = backend.bootstrap_db(database_url=url)
    if engine is None:
        sys.exit("seed: bootstrap_db failed")
    return engine, engine.getconn(), err


def _payment_tx(provider, payment_id):
    tx = base.PaymentProviderTransaction()
    if provider == "google_play":
        tx.provider = base.PaymentProvider.GooglePlayStore
        # Google's composite payment_id is "<token>|<order_id>", split once on the first '|'
        # (matches the backend's own split).
        token, _, order = payment_id.partition("|")
        tx.google_payment_token = token
        tx.google_order_id = order
    elif provider == "app_store":
        tx.provider = base.PaymentProvider.iOSAppStore
        # The wire payment_id is the transaction id; the backend row also wants the original tx id
        # (same value for a first purchase) and a web-line order id (empty).
        tx.apple_tx_id = payment_id
        tx.apple_original_tx_id = payment_id
        tx.apple_web_line_order_tx_id = ""
    elif provider == "stf":
        tx.provider = base.PaymentProvider.SessionFoundation
        tx.stf_order_id = payment_id
    else:
        sys.exit(f"seed: unknown provider {provider}")
    return tx


def _obfuscated_id(provider, vk):
    # The witnessed `platform_obfuscated_account_id` must equal what the backend recomputes from the
    # request-signed master key at redeem time (backend.py add_pro_payment binding), per provider.
    if provider == "google_play":
        # Google: the client sets setObfuscatedAccountId to the master pubkey verbatim, so the
        # attested id IS the raw 32-byte master pubkey; the redeem binds by byte-equality.
        return bytes(vk)
    if provider == "app_store":
        # Apple: appAccountToken = UUID(first 16 bytes of the master pubkey); the redeem binds by
        # equality against the same recomputed UUID (stored lowercased on receipt). Import the Apple
        # provider lazily -- its module pulls the Apple SDK -- so seeding a non-Apple payment doesn't
        # need it.
        from providers import app_store

        return app_store.uuid_from_master_pk(bytes(vk)).lower()
    return b""


def _round_up_to_utc_midnight(value):
    """Ceil to the next UTC midnight; a value already exactly at midnight stays put.

    Deliberately inlined rather than called from the backend. This was `base.round_datetime_to_next_day`
    until the backend moved it into its own test scaffolding, on the grounds that day-rounding is not
    something the backend does -- proof expiry lands on a per-account grid and every other instant is
    stored as it happened. So there is no stable backend function to call here, and substituting
    another internal would only queue up the next AttributeError.
    """
    value = value.astimezone(datetime.timezone.utc)
    midnight = value.replace(hour=0, minute=0, second=0, microsecond=0)
    return midnight if midnight == value else midnight + datetime.timedelta(days=1)


def cmd_payment(args):
    engine, conn, err = _open()
    try:
        vk = nacl.signing.VerifyKey(bytes.fromhex(args.master_pubkey))
        now = datetime.datetime.now(datetime.timezone.utc)
        plan = base.ProPlan.from_string(args.plan)
        if plan is None:
            sys.exit(f"seed: bad plan {args.plan}")
        # add_unredeemed_payment is @db.transactional: pass the connection positionally (it opens a
        # transaction for the call). The wrapper's first param is named `tx`, so `conn=` won't bind.
        backend.add_unredeemed_payment(
            conn,
            payment_tx=_payment_tx(args.provider, args.payment_id),
            plan=plan,
            purchased_at=now,
            expiry_at=_round_up_to_utc_midnight(now)
            + datetime.timedelta(days=args.expiry_days),
            platform_refund_expiry_at=base.EPOCH,
            platform_obfuscated_account_id=_obfuscated_id(args.provider, vk),
            err=err,
        )
        if err.msg_list:
            sys.exit(f"seed: add_unredeemed_payment failed: {err.msg_list}")
    finally:
        engine.putconn(conn)
        engine.close()


def cmd_revoke(args):
    # Revocation is keyed by the *provider* payment identifier (the generations-table refactor
    # replaced the old master-pkey-keyed set_revocation_tx). Revoking the payment marks its
    # generation revoked (revoked_at set, terminal), which is what get_pro_revocations surfaces.
    engine, conn, err = _open()
    try:
        now = datetime.datetime.now(datetime.timezone.utc)
        with db.transaction(conn) as tx:
            if args.provider == "app_store":
                ok = backend.add_apple_revocation(
                    tx, apple_original_tx_id=args.payment_id, revoke_at=now, err=err
                )
            elif args.provider == "google_play":
                token, _, _ = args.payment_id.partition("|")
                ok = backend.add_google_revocation(
                    tx, google_payment_token=token, revoke_at=now, err=err
                )
            else:
                sys.exit(f"seed: revoke unsupported for provider {args.provider}")
        if err.msg_list or not ok:
            sys.exit(f"seed: revoke failed (ok={ok}): {err.msg_list}")
    finally:
        engine.putconn(conn)
        engine.close()


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("payment", help="seed a witnessed-unredeemed payment")
    p.add_argument("--provider", required=True,
                   choices=["google_play", "app_store", "stf"])
    p.add_argument("--payment-id", required=True)
    p.add_argument("--master-pubkey", required=True, help="64 hex chars")
    p.add_argument("--plan", default="1m")
    p.add_argument("--expiry-days", type=int, default=30)
    p.set_defaults(fn=cmd_payment)

    r = sub.add_parser("revoke", help="revoke the generation for a provider payment")
    r.add_argument("--provider", required=True, choices=["google_play", "app_store"])
    r.add_argument("--payment-id", required=True,
                   help="same id used to seed the payment (app_store: tx id; google: <token>|<order>)")
    r.set_defaults(fn=cmd_revoke)

    args = ap.parse_args()
    args.fn(args)


if __name__ == "__main__":
    main()
