# Device groups: how an application uses them

This is the guide for an application that wants to support several devices on one Session account:
linking a new device, approving one, listing and removing devices, and handling the situations
that can go wrong. It describes *what to call and when*. The protocol behind it is in
`docs/protocol-v2.md`; the exact signatures and their full documentation are in
`include/session/core/devices.hpp` and `include/session/core/callbacks.hpp`.

## The one rule: the application is dumb

libsession works out where the device stands, owns every piece of state, and makes every protocol
decision. The application **draws what it is told and passes the user's choices back as calls**.
It never infers anything from swarm contents, and never keeps state of its own about device groups:
not a SAS, not a deadline, not a request id across a restart. Anything a screen needs is re-read
from libsession each time the screen is drawn, and the events below say when to read again.

## Concepts

- **Device group.** The devices that share an account's encryption keys. A device outside the
  group cannot read what the group shares, so a device that has restored an account from its
  recovery phrase still has to *join* the group before it is a full member.
- **Group identifier.** Each group has a fixed identifier (`device::GroupId`), shown as the first
  **4** emoji of `sas()` beside `created()` (all 21 emoji are there for an extended view). It tells
  apart groups the user has to choose between, and how old an unfamiliar one is. It is not a
  security check. **Show it only when more than one group is in view.** With a single group there
  is nothing to choose between, and its emoji beside a link request's emoji only gives the user two
  sets to confuse.
- **Link request.** How a device asks to join a group. Both devices show the same **7** emoji (21
  for an extended view), and the user confirms on *both* that they match.
- **Fork.** An account can end up with two groups, usually because a device started a new group
  when it should have joined the existing one. libsession alerts about this rather than resolving
  it; the user decides.

## Wiring it up

Implement `core::DeviceEvents` (re-exported as `client::DeviceEvents`). It has six methods, all
pure virtual, so none can be left out by accident:

| Event | Meaning |
|---|---|
| `link_request_added(LinkRequest)` | Another device asks to join this device's group. Prompt the user. |
| `link_request_ended(reqid, why)` | That request can no longer be answered (accepted elsewhere, replaced, expired). Close its prompt. |
| `device_membership_changed(device::Info)` | Another device joined the group, or was removed, or left. Tell the user ("Alice's laptop was added"). |
| `devices_replaced(device::map)` | The group's device list changed. Redraw the device screen. |
| `membership_changed(Membership)` | Where this device stands changed, or became known. Re-read `membership()` and act on it. |
| `group_appeared(GroupId)` | Another group has appeared alongside this device's: a fork. Alert the user. |

Pass a pointer to your implementation as `callbacks::devices`: `client::callbacks` for a `Client`
application, `core::callbacks` for one using `Core` directly. It must outlive the `Client` (or
`Core`), and for a `Client` also any delivery its dispatcher still holds. A `Client` delivers these
through its dispatcher, onto your thread; `Core` calls them on its own event loop. Either way a
handler must not block and must not throw.

Everything else is on `devices`: `client.core.devices` for a `Client` application. Each call has a
handler form, which takes a `result_function` and answers on the dispatcher or loop, and an
`await` form, which blocks the calling thread. Network operations (`request_link`) have only the
handler form. Failures carry an `Error` whose `code` is one of `core::err::*`.

At startup, and whenever the user changes them, describe this device with `update_info`: its
`type` (e.g. `device::Type::Session_CLI`), a short `description`, and its `version`. That is what
other devices show for it.

## Startup: membership drives everything

Call `membership()` at startup. Until the first fetch from the swarm completes it answers
`Unknown`, because the swarm may have changed while the application was down. **Do not prompt from
`Unknown`.** Wait for `membership_changed`, which fires when the first fetch makes the state known,
and on every change after, except one made by your own call (asking to join, starting a group,
renewing the device's identity). Re-read `membership()` after making those calls.

`membership()` returns the state, this device's group (when in one), and `others`: every other
group in the swarm, newest first, each with its id, when it was last seen, and whether the user
has dismissed it here.

| Membership | What it means | What to offer |
|---|---|---|
| `InGroup` | A full member. | Normal operation: the device screen, approving requests. If `others` has undismissed groups, a fork notice (see "Forks"). |
| `NoGroup` | Not in a group, and no group is in the swarm. | "No existing device group was found. Start a new one, or bring one of your other devices online to link this one?" Start → `start_group`. Otherwise wait: the state changes when a group appears. |
| `GroupsVisible` | Not in a group; groups it cannot read are in the swarm. | "Link to your existing devices" (see "Joining"). With one group in `others`, that is all; with several, list them by emoji and creation time for the user to pick from. Less prominently, "Start a new device group instead" → `start_group`, with a warning that it creates a second group the other devices will be alerted about. |
| `Waiting` | This device's link request is outstanding. | The waiting screen (see "Joining"). |
| `Removed` | Another device removed this one. | An alert: "This device was removed from your account's device group." Offer a way back: `renew_device_identity`, then join again. |
| `CutOff` | This device's group has disappeared from the swarm while another group is there. | A critical alert; this may be an attack. Never dismissable. Offer to join one of `others`. |
| `Displaced` | Another device now holds this device's place in its group, under this device's identity. | A critical alert (see "Forks and alerts"). Never dismissable. Offer `renew_device_identity`, then join again. |

`NoGroup` is deliberately the user's decision. It cannot be told apart from a group that expired
while all of the account's devices were offline for 30 days, and starting a group in that case
forks the account. An application that really does want to start a group automatically can call
`start_group` without asking, but that is its choice, not libsession's.

There is no "link later" call. If the user dismisses the prompt, do nothing: the state is
unchanged, and the next start (or the device screen) offers the choice again.

### Creating and restoring accounts

- **New account:** `globals.create_account(SeedSize::Bits128)` (13 words) or `Bits256` (25
  words). A new account gets its group at once and becomes `InGroup` with the first fetch.
- **Restored account:** `globals.restore_account(seed)`. No group is created. The first fetch
  makes the state `GroupsVisible` (join one) or `NoGroup`.

## Joining a group (the new device)

1. **Choose.** In `GroupsVisible`, take the group from `membership().others`. Usually there is
   exactly one: use it without asking, and without showing its emoji. Only when there are several
   does the user pick, by group emoji and creation time.
2. **Ask.** `request_link(group, cb)`. It uploads the request and answers once the swarm has stored
   it, with the SAS and the deadline (10 minutes). Errors: `err::unknown_group` (no longer in the
   swarm), `err::network_unavailable`, `err::store_failed` (worth retrying), `err::already_registered`
   (already in that group), `err::removed` (displaced: renew the identity first).
3. **Show the waiting screen**, drawn from `outgoing_link_request()` every time it is opened: the 7
   emoji (21 extended), a countdown to `expires`, and a **"These match"** action. Tell the user to
   open Session on one of their existing devices, where a matching prompt will appear.
4. **Confirm.** When the user says the emoji match, call `confirm_link`. After that,
   `outgoing_link_request()->confirmed` is true, so the screen shows "Waiting for your other device
   to approve".
5. **Done** when `membership_changed(InGroup)` arrives. If the other device approved before the
   user confirmed here, joining happens inside the `confirm_link` call.

The waiting screen may be closed and reopened at will; it survives a restart while the request is
live. If the deadline passes unanswered, `membership_changed` reports the device back in
`GroupsVisible`/`NoGroup`; offer to try again. Asking again replaces the request with one that has
a new SAS, which needs confirming again.

An approval can arrive after the deadline has passed here: the other device approved in time, but
this one fetched the message late. Then `membership_changed(Waiting)` comes back, and
`outgoing_link_request()` returns that request with `accepted` set, past its `expires`. Show it
without the countdown: "Your other device approved this. Do these emoji match what it showed?"
Joining still needs `confirm_link`. If the user had already confirmed a request and then asked
again, an approval of the earlier one still admits the device; libsession sorts that out.

**Why the confirmation on the new device matters.** Anyone who holds the account's recovery phrase
(a removed device, a stolen backup) can publish a fake group. A device that asks *that* group to
let it in would be admitted by the impostor, and from the new device alone that looks exactly like
success. The real group can't even read such a request, so no prompt ever appears on the user's
real devices. Confirming on the new device is what catches this: **the user should only press
"These match" after seeing the same emoji on one of their own existing devices.** Never confirm
automatically.

## Approving a request (an existing device)

1. On `link_request_added`, prompt the user with the requesting device's description, type,
   version, when it asked, and the 7 emoji (21 extended). Consider holding the prompt until the
   user has stopped typing for a few seconds, so that a keystroke can't answer it by accident.
   Re-read `incoming_link_requests()` when drawing the prompt rather than trusting a copy held from
   earlier: a request can be replaced or answered in between.
   If `replaces` is set, the request comes from a device already in the group, under the same
   identity: usually one that lost track of having joined, such as one restored from a backup.
   Say so plainly, and show `replaces` (its current description and when it last updated) beside
   the request: "This will replace *Alice's laptop* in your device group." The emoji check matters
   as much as for a new device, since someone holding the recovery phrase could ask under that
   identity too.
2. Offer three answers:
   - **Approve:** `accept_request(id)`. Only if the user confirms the emoji match what the new
     device shows.
   - **Ignore:** `ignore_request(id)`. Local only; another of the user's devices may still approve
     it, which is the normal case when the user is approving elsewhere.
   - **"I don't recognise this":** `ignore_request(id, true)`. Also deletes it from the swarm, so
     devices that haven't fetched it yet never see it. A device that already has it can still
     approve it until it expires, so word this as "stop other devices seeing it", not "block it".
3. Close the prompt on `link_request_ended`, whatever the reason; the reason is there if you want
   to say something like "approved on another device". It does not fire for this device's own
   accept or ignore: close the prompt when that call returns.

`accept_request` answers false if the request can no longer be accepted (approved elsewhere,
replaced, expired, the device removed, or this device has left the group meanwhile). That is not an
error: close the prompt. Accepting a replacement also gives the group a new account key; there is
nothing for the application to do about that.

Request ids are counters for this run only. Never persist or display them.

## The device list

`devices(true, false, true)` gives every device that is or was in the group, by id. `state` says
which:

- `Registered`: in the group. Show its description, type, version and `timestamp` (when it last
  updated its information).
- `Kicked`: removed, at `kicked`. `Left`: left of its own accord, at `kicked`.
- `Pending` devices are only asking to join, and appear as link requests rather than in the list.

A device that was removed before this one joined appears as a bare tombstone with nothing to show
for it (an empty description). Leave those out of the list.

Redraw on `devices_replaced`. `device_membership_changed` comes first, once for each other device
that joined or stopped being in the group, with its record as it now stands; use it for a notice
rather than for the list. It does not fire for this device's own `accept_request` or
`remove_device`, nor for the devices of a group this device has just joined.

To remove a device, call `remove_device(id)` behind a confirmation
that makes its permanence clear: **a removed device can never rejoin under the same identity**. It
can only come back by generating a new one (`renew_device_identity`) and being approved again, like
a new device. `remove_device` answers false if the device is no longer in the group (or this one
isn't), which is not an error. This device cannot remove itself.

## Forks and alerts

- **Another group appears** (`group_appeared`, while `InGroup`). Alert the user: "Another device
  group exists alongside yours". Two groups are now in view, so show the emoji and creation time of
  both, this device's included, so the user can tell them apart. Usually one of the user's
  devices started a new group by mistake. Offer two things:
  - **Dismiss:** `dismiss_group(group)`. Remembered on this device only; each device decides for
    itself. A different group still alerts.
  - **Switch to it:** see "Switching groups".
- **Cut off** (`membership_changed(CutOff)`). Treat this as critical: the device's group is gone
  from the swarm and another is there, which may mean someone with the recovery phrase replaced it.
  It is never dismissable. Offer to join one of `others`.
- **Displaced** (`membership_changed(Displaced)`). Critical, and never dismissable. The group has
  moved on to keys this device doesn't hold, under this device's own identity. Either the user
  restored this device elsewhere and approved the copy as a replacement, or someone with a copy of
  this device's data has taken its place. Say both: "Another device has taken this device's place
  in your device group. If you didn't restore it on another device, someone may have a copy of
  this device's data." The device stops acting for the group by itself. The way back is
  `renew_device_identity()`, then joining as a new device; the user should also remove the old
  identity from one of their other devices if they don't recognise what now holds it.
- **Removed** (`membership_changed(Removed)`). Tell the user. If they want the device back,
  `renew_device_identity()` gives it a new identity; it then joins like any new device. Messages
  and the account's configs are kept.

## Starting a group

`start_group()` creates a group with this device as its only member. It is valid from `NoGroup`, and
from `GroupsVisible`, where it creates a group *alongside* the existing ones. That deletes nothing:
the other devices get `group_appeared`, so a mistake can be undone. A device that was `Waiting`
drops its request. It fails with `err::membership_unknown` before the first fetch,
`err::already_registered` from a group, and `err::removed` for a removed or displaced device (which
must `renew_device_identity` first).

## Switching groups

A device in one group can ask to join another, for example to undo starting a group by mistake.
Call `request_link` with the other group, exactly as for joining. The device stays a working member
of its current group while it waits (`membership()` stays `InGroup`; the pending request shows in
`outgoing_link_request()`). The same confirmation is needed. Once admitted, libsession leaves the
old group by itself: it tells the remaining members, or deletes the group if this was its only
member. It dismisses the old group, and takes on the new group's devices and keys.

## Do not

- Prompt from `Membership::Unknown`.
- Keep a SAS, deadline or request id yourself, or show a SAS from anywhere but a fresh read.
- Confirm a link (`confirm_link`) or approve a request (`accept_request`) without the user
  comparing the emoji on both devices.
- Start a group for a restored account without the user choosing to, unless that is a deliberate
  policy of your application.
- Hardcode the numeric values of `device::State` or `device::Membership`.
- Block or throw in a `DeviceEvents` handler.
