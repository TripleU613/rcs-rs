# rcs-rs

A Rust RCS engine for open source messaging apps.

The goal is to let an existing SMS app add carrier-backed RCS through a reusable
library. The app retains its conversation UI and SMS transport. The RCS engine
handles service provisioning, registration, capabilities and RCS messaging.

The shipping target is a normal APK on stock and custom Android, including
vanilla builds without GApps. The engine must authenticate its own client;
Google Messages, microG and root are laboratory tools, not shipping requirements.
That independent deployment remains unproven.

**Status: Rust configuration discovery works with reference caller credentials.**
The Rust ACS client obtains a real DroidGuard challenge and retains its session
cookie. Rust consent lookup also works with genuine caller-supplied platform
identity/proof inputs. Independent probes completed real SIM authentication and
obtained a carrier temporary token. That Google-specific ACS path returns an invalid
configuration without subscriber credentials; the Rust number-verification RPC also reaches
Google, whose verification record remains throttled.
Discovery now includes an optional actual installed GMS version. A controlled
comparison found that omitting it hid the direct carrier-authentication route;
the corrected Rust request receives direct TS43 support and a carrier endpoint.
Signed read-only number lookup succeeds with the client's owned credentials,
but currently returns no verified-number records.
Registration and Google Messages interoperability remain unverified.
The [ordinary-client admission record](docs/research/ordinary-client.md) tracks
own-APK permissions and backend checks separately from the reference-client work.
An own-APK cellular probe reached the standard carrier ACS and, with a temporary
identifier app-op lab grant, received a provisioning body. Its XML is unfinished
and its profile selects SIM AKA, the IMS APN and single registration; this does
not establish a usable session or ordinary-app support for those operations.
Installed-code and own-UID checks now identify separate SIM-auth and restricted
IMS-request gates. Passive IMS observation/socket binding worked; the proxy send
failed with `ENETUNREACH`. Default DNS returned only IPv4 and observed IMS
base-link addresses were IPv6, but the underlying cause remains undetermined.
No SIP response or registration was obtained.

Success means this library sends a text to current Google Messages and receives
a reply over **verified RCS**, independently of Google Messages on the sending
device. Provisioning and registration are intermediate milestones.

See the [Google RCS interoperability plan](docs/superpowers/plans/2026-10-16-google-rcs-interoperability.md)
and the [bootstrap design](docs/superpowers/specs/2026-10-16-rcs-bootstrap-design.md).

## Reuse first

[rust-rcs-client](https://github.com/Hirohumi/rust-rcs-client) already implements
auto-configuration and messaging, with
[rust-rcs-core](https://github.com/Hirohumi/rust-rcs-core) underneath it. Evaluate
these before writing another SIP/MSRP stack. The [pinned audit](docs/research/upstream.md)
found working parser/linkage paths, secret logging and incomplete platform support.
Their upstream claims are not verification of Tello or Google Messages compatibility.

[Evaluation patches](patches/upstream/README.md) now suppress credential logging,
fix trust-root loading and reject truncated provisioning. They are tested against
the pinned sources and remain separate from the shipping crate.

## Development data

Use synthetic fixtures in this repository. Keep SIM identifiers, phone numbers,
tokens, provisioning credentials, APKs and raw device captures outside it.
The bootstrap uses tonic for TLS/HTTP2/gRPC and prost for protobuf. Reference
application credentials are supplied externally and are not bundled.

## Run the bootstrap probe

Set `RCS_APP_PACKAGE`, `RCS_APP_CERT_SHA1` and `RCS_API_KEY_FILE` (a private
plaintext file), then run:

```sh
cargo run --example discover -- MCC MNC DEVICE MANUFACTURER PACKAGE_VERSION [GMS_VERSION]
```

The probe sends MCC/MNC and device/application metadata, defaulting GSF Android
ID to zero. It accepts no phone number, IMSI or IMEI. Backend admission may restrict
the application credentials. `DEVICE` is Android's `Build.DEVICE`, not its model
name. Supply the actual installed Play Services or compatible implementation's
version with `Probe::with_gms_version` or the final CLI argument when present;
the minimal request without it can receive different provisioning routes.
`Probe::with_gsf_android_id` (CLI: optional `RCS_GSF_ANDROID_ID`) passes the actual
signed-decimal GServices `android_id` read in the authorized client context.
Leave it unset when unknown. Shell/Phone lookups can differ from Messages due
to provider access rules; neither Settings.Secure.ANDROID_ID nor a check-in ID
is an established substitute. On this test line, the actual ID and zero returned
identical onboarding flags and policy.
Output contains configuration flags and the ACS
host, without response tokens.

The separate initial ACS probe takes an HTTPS endpoint and client metadata:

```sh
cargo run --example challenge -- HTTPS_URL VENDOR MODEL OS_VERSION CLIENT_VENDOR CLIENT_VERSION RCS_PROFILE RCS_VERSION [--droidguard]
```

`AcsSession::initial_challenge(&parameters, None)` omits client-authenticity
advertising. Explicit `Some(ClientAuthenticity::DroidGuard)` (CLI:
`--droidguard`) advertises the Google method; the host must supply its genuine
proof separately. Omission does not bypass a provider's authenticity requirement.
The recovered UPI path continues to advertise its distinct `goog-mls-upi` method.

`AcsSession::msisdn_challenge(&parameters, own_number, None)` begins number-based
provisioning without IMSI, IMEI, a Google API key or a client-authenticity
advertisement. Its third argument accepts the same explicit authenticity choice.
The number must use international `+digits` form, at most 15
digits. This explicit call can trigger a provider verification SMS. OTP submission,
accepted provisioning and registration are not implemented by this method.
Supply provider-formatted metadata: for example, vendor `RCRS` and version
`RCRS-0.1`, rather than an APK's unformatted version name.

`cargo run --example get_consent -- /private/input.json` performs consumer
consent lookup. The example documents its private-file inputs. It requires a
genuine full-flow IID, checkin identity, owned public key and DroidGuard proof
or a valid backend-issued cached token; the crate does not fabricate these.

`verification::SyncResponse::decode` and `ProceedResponse::decode` inspect raw
protobuf captures offline. They expose TS43 challenges and per-record failures,
retain exact verification/context bytes, and redact private fields in diagnostics.
They do not send verification requests or validate returned tokens. The decoder
has also been checked against the private pending, failed and throttled captures.

`verification::initial_sync` sends one initial verification request using genuine
SIM/caller facts. `verification::proceed_ts43_unsigned` submits a genuine full
carrier JSON response while preserving the original verification/context bytes.
It rejects public-key updates because signed follow-ups are not implemented.
Neither function retries automatically or treats outer RPC success as verification.
`Verification::private_id_token` exposes the optional `id_token` parameter for
the UPI provisioning step. It is unvalidated service data; its presence is not
proof of verified identity, JWT validity or registration.

`verification::read_verified_numbers` queries this client's existing RCS number
records without starting number verification. Supply the read API's distinct
project-specific IID, a fresh timestamp and the owned persisted EC key's DER
signature over `read_numbers_signing_input(iid, timestamp)` using SHA256withECDSA.
Keep that IID and timestamp identical in `ReadNumbersRequest`, and supply the
actual caller certificate, package and nonce. The library bounds the signature
but does not verify key ownership or freshness. Empty results stay empty, and
quota errors never cause automatic retries. Private phone/token accessors return
unvalidated service data; original records retain timestamp and unknown fields.
The exported Rust API has also returned an empty result against the live service;
it is not successful subscriber verification or RCS registration.

```sh
cargo run --example verify_number -- sync /private/session.json /private/new-response.pb
cargo run --example verify_number -- proceed /private/session.json /private/new-proceed.pb
```

The example documents the session JSON fields in its source. It reserves a new
mode-600 response file, never overwrites a capture, and may leave an empty file on
failure. A raw DroidGuard proof must match the requested RPC; a valid cached token
can be reused. Carrier EAP-AKA/HTTP execution still uses private research tooling,
not this library. The corrected Proceed payload has not yet passed live verification.

`AcsSession::upi_challenge` implements the recovered UPI challenge request.
Its context exposes the private DroidGuard input map and MLS signing bytes.
Supply a genuine platform result and an owned P-256 participant signature to
`UpiChallenge::provision`; it verifies the signature and sends one `/provision`
request. The context holds exclusive session access until consumed or dropped.
This path has synthetic wire and localhost transport coverage. A separate live
UPI challenge probe obtained a nonce/cookie; credential-bearing UPI provisioning
and service registration remain unverified.

`cargo test --all-targets` runs the synthetic protocol and localhost transport
checks. Formatting and strict Clippy also pass. No live credentials are needed
for these tests.

See [recovered GApps behavior](docs/research/gapps-bootstrap.md) for artifact
identities, wire evidence, live checks and remaining blockers.
The [provider-access record](docs/research/provider-access.md) separates this
subscription's UPI credential/provisioning path from Android single registration
and the carrier temporary-token route.

Nothing has been pushed or published.

The [ordinary Android capability probe](tools/android-admission-probe/README.md)
builds as a small self-targeted instrumentation APK without Google SDKs. It reports
permission gates and identifier availability without exporting subscriber values;
it neither changes the SMS role nor tests RCS registration.
