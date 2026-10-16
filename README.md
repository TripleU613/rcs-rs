# rcs-rs

A Rust RCS engine for open source messaging apps.

The goal is to let an existing SMS app add carrier-backed RCS through a reusable
library. The app retains its conversation UI and SMS transport. The RCS engine
handles service provisioning, registration, capabilities and RCS messaging.

**Status: initialized; implementation has not started.** No Google Messages
interoperability has been demonstrated. A reachable configuration server alone
does not establish that a provider accepts independent clients.

Success means this library sends a text to current Google Messages and receives
a reply over **verified RCS**, independently of Google Messages on the sending
device. Provisioning and registration are intermediate milestones.

See the [Google RCS interoperability plan](docs/superpowers/plans/2026-10-16-google-rcs-interoperability.md)
and the [bootstrap design](docs/superpowers/specs/2026-10-16-rcs-bootstrap-design.md).

## Reuse first

[rust-rcs-client](https://github.com/Hirohumi/rust-rcs-client) already implements
auto-configuration and messaging, with
[rust-rcs-core](https://github.com/Hirohumi/rust-rcs-core) underneath it. Evaluate
these before writing another SIP/MSRP stack. Their upstream claims are not
verification of Tello or Google Messages compatibility.

## Development data

Use synthetic fixtures in this repository. Keep SIM identifiers, phone numbers,
tokens, provisioning credentials, APKs and raw device captures outside it.
No upstream source has been copied and no dependencies have been selected yet.

Nothing has been pushed or published.
