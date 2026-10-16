# rcs-rs

A Rust RCS engine for open source messaging apps.

The goal is to let an existing SMS app add carrier-backed RCS through a reusable
library. The app retains its conversation UI and SMS transport. The RCS engine
handles service provisioning, registration, capabilities and RCS messaging.

**Status: Rust configuration discovery works against the live service.**
The Rust ACS client obtains a real DroidGuard challenge and retains its session
cookie. Rust consent lookup also works with genuine caller-supplied platform
identity/proof inputs. An independent initial Sync selected TS43 verification;
subscriber provisioning, registration and Google Messages interoperability remain
unverified.

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
The bootstrap uses tonic for TLS/HTTP2/gRPC and prost for protobuf. Reference
application credentials are supplied externally and are not bundled.

## Run the bootstrap probe

Set `RCS_APP_PACKAGE`, `RCS_APP_CERT_SHA1` and `RCS_API_KEY_FILE` (a private
plaintext file), then run:

```sh
cargo run --example discover -- MCC MNC DEVICE MANUFACTURER PACKAGE_VERSION
```

The probe sends MCC/MNC and device/application metadata, with GSF Android ID
zero. It accepts no phone number, IMSI or IMEI. Backend admission may restrict
the application credentials. Output contains configuration flags and the ACS
host, without response tokens.

The separate initial ACS probe takes an HTTPS endpoint and client metadata:

```sh
cargo run --example challenge -- HTTPS_URL VENDOR MODEL OS_VERSION CLIENT_VENDOR CLIENT_VERSION RCS_PROFILE RCS_VERSION
```

`cargo run --example get_consent -- /private/input.json` performs consumer
consent lookup. The example documents its private-file inputs. It requires a
genuine full-flow IID, checkin identity, owned public key and DroidGuard proof
or a valid backend-issued cached token; the crate does not fabricate these.

`cargo test --all-targets` runs the synthetic protocol and localhost transport
checks. Formatting and strict Clippy also pass. No live credentials are needed
for these tests.

See [recovered GApps behavior](docs/research/gapps-bootstrap.md) for artifact
identities, wire evidence, live checks and remaining blockers.

Nothing has been pushed or published.
