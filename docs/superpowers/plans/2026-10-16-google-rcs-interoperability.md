# Google RCS Interoperability Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking. Keep the network discovery tasks sequential; their results determine the implementation route.

**Goal:** Deliver an open source Rust library that can send a person-to-person RCS text to current Google Messages and receive an RCS reply, then expose that capability to an existing open source SMS application.

**Architecture:** A Rust engine handles provisioning, registration, capability exchange and messaging. A small Android host supplies subscription-specific network and authentication access. Prefer an admitted standards-based RCS service with network interconnection to Google; investigate direct Google service access if the selected subscription requires it. Choose the actual route from observed evidence.

**Tech Stack:** Rust; evaluate the existing Apache-2.0 `rust-rcs-client` and `rust-rcs-core`; Android/Kotlin for platform APIs; GSMA provisioning and negotiated RCS protocols. Use the existing upstream runtime and parsers where they survive testing. Select an MLS implementation only when the encryption integration requirements are established.

**Spec:** [RCS bootstrap design](../specs/2026-10-16-rcs-bootstrap-design.md), expanded by the user's requirement for actual Google Messages interoperability.

## Global constraints

- "Use synthetic fixtures in this repository."
- "Keep secrets out of Debug output, errors, fixtures and logs."
- "Do not import another app's private tokens as the library's authentication mechanism."
- "Unsupported flows produce explicit errors rather than simulated progress."
- "No UI, SMS database migration or root module belongs in this milestone."
- The last constraint applies to bootstrap; a minimal Android test host and later existing-app integration are separately scoped below.
- Provider admission, registration, message delivery and encryption are distinct results. No stage substitutes for a later stage's acceptance test.
- Keep carrier/device-specific support explicit. A successful rooted test does not establish support for ordinary installed apps.

## Review focus

1. A lost send acknowledgement leaves delivery uncertain: never automatically duplicate it through SMS; test in Task 5.
2. A subscription changes while requests are pending: cancel the old work and discard its credentials; test in Tasks 2 and 6.
3. A server redirects or a peer supplies hostile XML/CPIM: preserve credential boundaries and bound parsing; test in Tasks 2 and 4.
4. Capabilities are missing, stale or contradictory: advertise only implemented features and avoid unsupported routing; test in Task 4.
5. A conversation negotiates encryption the library cannot handle: report the incompatibility without falsely showing plaintext as secure; test in Task 7.

## Definition of done

The first interoperability proof requires two different active test identities:

- A: our independently authenticated Rust client, initially hosted on the test Android phone.
- B: a separate device with a current Google Messages build, working RCS and a reachable test number.

A sends a uniquely identified text. B receives it as RCS and replies. A receives
the reply. Message details on B and redacted protocol events on A establish the
transport; successful HTTP/SIP submission alone is insufficient. Google Messages
on A must not authenticate, relay or send on the library's behalf. Prevent
competing registrations while testing, using supported deactivation procedures
and their propagation time. Keep original app data intact.

Minimum repeatability: ten short messages in each direction, including Unicode,
and a reconnect test with no duplicates. Capture actual delivery evidence and
the encryption state. A transport-secured but non-E2EE proof, if the negotiated
service supports it, is a limited milestone. Encrypted interoperability and
reliable app integration are additional acceptance gates.

## What is verified today

As of 2026-10-16:

- Rust discovery, initial ACS challenge handling and consumer consent lookup work against the live services. Initial Sync and unsigned TS43 Proceed are implemented with synthetic wire/transport checks. A live Rust Sync still returns a throttled verification record; there is no admitted session or messaging engine.
- Current Messages build 324451063 and original GMS 26.37.37 are now the main bootstrap references. The 2022 APK is historical evidence only. [Recovered behavior](../../research/gapps-bootstrap.md) records real SIM authentication, carrier temporary tokens, the corrected Proceed field tag and unresolved admission.
- Google documents interconnection between carrier RCS systems through Jibe Hub [1]. That makes a carrier route a credible approach; it does not prove Tello admits this client.
- Android's single-registration APIs require privileged installation and the default SMS role. Capability exchange and restricted network access also have permission constraints [2]. A normal SMS role grant is insufficient for that route.
- The pinned upstream revisions passed library test builds (client: zero tests; core: four tests) and a separate four-test consumer harness checked actual host linkage, WAP parsing, certificate loading, Linux stubs and synthetic credential logging. See the [bounded reuse audit](../../research/upstream.md); this does not establish live interoperability.
- `RcsEngine::send_message` hardcodes `recipient_supports_one_to_one = false` and `recipient_supports_standalone = true`. Session code exists, but the send decision does not discover actual recipient capabilities [3].
- The upstream Linux ICC implementation returns no SIM channel. Debug code logs sensitive values, including derived GBA material [4]. Both need attention before using real identities in that stack.
- GSMA publishes an interoperable MLS-based RCS encryption specification. Google announced cross-platform encrypted RCS rollout in May 2026 [5,6]. An old APK is insufficient as our only encryption reference.

## Route decision

```text
Rust client + Android host
    -> authorized provisioning and authentication
    -> admitted RCS service
    -> interconnection where needed
    -> Google Messages recipient
```

| Route | Evidence required | Consequence |
| --- | --- | --- |
| Carrier standard provisioning, independent registration | Configuration, supported authentication and successful registration for our client | Reuse/extend the Rust stack; test delivery through the provider's interconnection |
| Carrier single registration | Device/carrier support, required permissions, working SIP delegate | Use the Android IMS adapter; standalone Rust SIP registration is not this route |
| Direct Google service | Observed current bootstrap, independently obtainable authentication and accepted service session | Implement that specific service adapter; do not assume all post-bootstrap traffic is standard SIP |
| No admitted route on this subscription | Exact rejection or unavailable platform requirement, with a controlled reference comparison | Record a blocker and the requirement for proceeding; a parser or self-hosted server cannot count as Google interoperability |

Running our own RCS server is not an immediate fallback: reaching real subscriber
networks would still require routing/interconnection. RCS Business Messaging and
Messages for Web do not implement the requested independent subscriber client.

## File and ownership map

These are planned responsibilities, not files already implemented. Keep one
crate initially; add separate crates only if actual platform packaging needs it.

| Path | Responsibility |
| --- | --- |
| `docs/research/upstream.md` | Pinned revisions, build/link results, reuse decision and license provenance |
| `docs/research/provider-access.md` | Redacted route decision, actual requirements and blockers |
| `docs/interop/google-messages.md` | Reproducible two-device procedure and observed results |
| `Cargo.toml`, `Cargo.lock`, `src/lib.rs` | Build and tested application-facing exports after a viable route exists |
| `src/provisioning.rs` | Validated provisioning entry point and structured progress/errors |
| `src/platform.rs` | Required host network/authentication operations for the chosen route |
| `src/client.rs` | Session lifecycle and registration state |
| `src/capabilities.rs`, `src/messaging.rs` | Supported service selection, text send/receive and delivery events |
| `src/encryption.rs` | Negotiated encryption integration, only in Task 7 |
| `examples/probe.rs` | Redacted diagnostic host for offline fixtures and supported desktop operations |
| `android/probe/` | Minimal Android platform host; exact Gradle/ABI layout selected in Task 2 |
| `tests/fixtures/`, `tests/bootstrap.rs`, `tests/messaging.rs` | Synthetic fixtures and meaningful protocol tests |

Patch upstream protocol behavior at its shared implementation point rather than
copying it into a parallel wrapper. If source must be vendored to make patches,
place the two repositories as siblings under `vendor/`, preserve licenses and
notices, and record every upstream revision and local patch. Do not commit the
temporary evaluation clones, build output or dependency caches.

## Task 1: Establish the reusable baseline

**Files:** Create `docs/research/upstream.md`; modify dependency/patch files only after this decision.

**Consumes:** The two pinned upstream revisions above.
**Produces:** A reproducible build/link result and a list of reusable paths and required fixes.

- [x] Inspect provisioning, registration, message dispatch and platform boundaries.
- [x] Run `cargo check` against both sibling repositories; result: pass with warnings.
- [x] Reproduce with the pinned sibling checkouts and private evaluation harness (exact paths/results in `docs/research/upstream.md`):

```bash
mkdir -p private/upstream
git clone https://github.com/Hirohumi/rust-rcs-client private/upstream/rust-rcs-client
git clone https://github.com/Hirohumi/rust-rcs-core private/upstream/rust-rcs-core
git -C private/upstream/rust-rcs-client checkout 720b42fad99d6d1f71dd89dcb11293245a0960d7
git -C private/upstream/rust-rcs-core checkout f2f351c467ba6f2aa9a786647845b6ad21f300c5
cargo check --manifest-path private/upstream/rust-rcs-client/Cargo.toml
cargo test --manifest-path private/upstream/rust-rcs-client/Cargo.toml --lib
```

- [x] Distinguish no tests from passing behavioral tests. Test linking an actual host, since type checking does not establish platform callback availability.
- [x] Audit the paths listed in the source references for raw auth/config/body logs, TLS handling, callback nullability and platform stubs. Record findings with symbols and caller locations.
- [ ] Suppress/remove sensitive protocol logs before any live evaluation. Pin this with synthetic sentinel credentials and assert that captured output lacks each sentinel.
- [ ] Preserve licenses; commit the baseline decision and any narrowly necessary patches. Do not bulk-fix unrelated warnings.

**Exit:** A buildable, linked evaluation host with no known secret logging on the exercised path; explicit supported platform operations. This is not a network-access success.

## Task 2: Determine how this subscription can admit our client

**Files:** Create `docs/research/provider-access.md`, `docs/interop/google-messages.md`; create `android/probe/` only to exercise platform operations that the selected route requires.

**Consumes:** Task 1's safe evaluation host and two controlled test identities.
**Produces:** One selected route, its authentication/network requirements, and redacted evidence; or an exact blocker.

- [ ] Verify B has current Google Messages with RCS connected. Record its actual app version, provider indication and encryption state. Do not treat the 2022 APK as a current reference.
- [ ] Inventory A's carrier configuration, single-registration feature, available SIP delegate service and permission grants. Separate ordinary-app access from privileged/root-assisted laboratory access.
- [ ] Trace current reference provisioning on the test subscription: ACS discovery, identifiers required, client metadata, HTTP state/cookies, verification challenge, cellular routing and final service configuration. Keep captures private; record sanitized field names and transitions.
- [ ] Where Google-specific bootstrap is present, inspect that path separately. Determine whether the service uses an app assertion, attestation, token exchange or proprietary transport. Test these hypotheses; do not infer them from the current missing URL or the unrelated integrity checker result.
- [ ] Implement only the smallest independent probe for the observed flow. Use our client's own session and number verification. Do not reuse Google Messages' private bearer tokens as a shortcut to a claimed success.
- [ ] Exercise the required Android network/SIM operations. A permission denial must identify the API and privilege requirement; a Linux stub must not silently stand in for a SIM response.
- [ ] Obtain a valid authorized configuration/session, or record the exact status/challenge and missing requirement. Honor server retries; avoid repeated verification requests when throttled.
- [ ] Test cancellation on SIM switch and credential non-forwarding across a synthetic cross-origin redirect before running the real flow.
- [ ] Commit only redacted evidence and the route decision. A route change updates the implementation detail for Tasks 3–4 before their code is written.

**Exit:** Independent admission is demonstrated, or feasibility remains explicitly blocked. Do not invest in an app facade while this gate is unresolved.

## Task 3: Complete provisioning and maintain the admitted session

**Files:** Create `Cargo.toml`, `Cargo.lock`, `src/lib.rs`, `src/provisioning.rs`, `src/platform.rs`, `src/client.rs`, `examples/probe.rs`, `tests/bootstrap.rs` and synthetic fixtures; patch reused upstream code at the shared source.

**Consumes:** Task 2's selected route, configuration format and authentication requirements.
**Produces:** A registered/ready client and structured failure/retry states usable by Task 4.

- [ ] For the selected route, write fixture tests that fail before integration: authorized configuration, service disabled, malformed/truncated response, expired credentials, transient failure with retry timing and failed authentication. Include MCC/MNC width validation where discovery is used.
- [ ] Wire the verified upstream provisioning parser/engine where applicable. Require every field actually needed by the chosen transport; do not accept incomplete configuration as ready.
- [ ] Supply the platform operations through the Android host. Keep subscription binding and credential lifetime explicit. Return an unsupported-operation error for unavailable operations.
- [ ] If independent IMS is selected, verify challenge/response, authenticated REGISTER, refresh and deregistration. If single registration is selected, verify delegate/registration callbacks. If a proprietary service is selected, verify its actual authenticated ready event instead of inventing a SIP registration.
- [ ] Test rejected authentication, stale nonce where relevant, reconnect, expiry during a request and cancellation. Assert that no failure path emits ready.
- [ ] Run the live flow once; record the server-confirmed session state and expiry without credentials. Commit the smallest working bootstrap integration.

**Exit:** Independently authenticated session ready for the chosen messaging route. Registration alone remains an intermediate milestone.

## Task 4: Discover capabilities and exchange one text in both directions

**Files:** Create `src/capabilities.rs`, `src/messaging.rs`, `tests/messaging.rs`; modify `src/lib.rs`, `src/client.rs`, the probe and upstream dispatch/receipt code; update `docs/interop/google-messages.md`.

**Consumes:** Task 3's admitted session and the reference peer from Task 2.
**Produces:** Real capability results, text send/receive events and separately identified submission/delivery events.

- [ ] Inspect the provider's required capabilities mechanism, including OPTIONS or presence where applicable. Replace upstream hardcoded recipient support with observed capability results. Test unknown/expired/contradictory capabilities and a peer without RCS.
- [ ] Test service selection for the negotiated peer: standalone and session chat must not be assumed interchangeable. Exercise the actual selected path before enabling it.
- [ ] For a standard SIP route, test CPIM framing, identity normalization, SIP MESSAGE or INVITE/SDP/MSRP as negotiated, and IMDN receipts. For another admitted transport, map its observed equivalent. Reuse tested upstream implementations rather than reimplementing the entire protocol.
- [ ] Add synthetic tests for Unicode, truncated input, excessive lengths, duplicate message IDs, malformed headers and unrelated receipt IDs. Enforce configured limits before allocating or sending.
- [ ] Advertise only supported capabilities, including encryption. Do not advertise groups, attachments or encrypted formats before their implementation.
- [ ] Send one unique text A → B with SMS fallback absent from the probe; verify B's message details identify RCS. Reply B → A and correlate the receive event to that conversation.
- [ ] Record encryption state and distinguish server acceptance from delivery to B. If a negotiated requirement blocks delivery, record that requirement and implement it before claiming the exchange succeeded.
- [ ] Commit the first demonstrated exchange with redacted version/provider evidence.

**Exit:** Actual two-way Google Messages RCS, independent of Google Messages on A. A mock peer is insufficient.

## Task 5: Make text messaging repeatable under failures

**Files:** Modify lifecycle, capability and messaging implementations and their tests; extend `docs/interop/google-messages.md`.

- [ ] Test ten uniquely identified texts in each direction, including emoji and multi-byte text near the configured length limit. Verify payload equality and one receive event per ID.
- [ ] Drop transport after sending but before acknowledgement. Mark the outcome uncertain; test that the app is not instructed to resend through SMS automatically.
- [ ] Disconnect during a session, reconnect, refresh registration and repeat the two-way exchange. Test late and duplicate receipts without reversing a terminal state.
- [ ] Test remote party offline then online, capability cache expiry and local process restart. Record the provider's observed offline-delivery behavior rather than assuming store-and-forward.
- [ ] Keep reconnection bounded with server backoff. Verify a deterministic synthetic disconnect sequence reaches a stable state without tight retry loops.
- [ ] Commit failure handling plus the repeatability evidence.

**Exit:** Repeatable two-way text delivery with defined ambiguous outcomes and no duplicate fallback sends.

## Task 6: Expose the proven flow to an open source SMS app

**Files:** Modify `src/lib.rs` and lifecycle/messaging modules; add the smallest required Android ABI binding and one integration sample; document it in `README.md`.

- [ ] Define the minimal public API from working behavior: start/stop, progress/readiness, query supported recipient capabilities, send text and receive message/delivery/error events. Derive exact types from the selected flow; avoid publishing speculative interfaces before Tasks 2–5.
- [ ] Exercise the API from a small Android host using the same permissions intended for the eventual SMS app. Document if privileged installation remains required. Provide a debug-only lab path separately if needed.
- [ ] Test background suspension, process recreation and subscription change. Cancel pending work on SIM change, discard its secrets and prevent delivery to the wrong subscription.
- [ ] Let the SMS app retain storage and conversation UI. Show RCS availability and uncertain-send state; require explicit transport decisions where duplicate delivery is possible.
- [ ] Validate callback ownership, cancellation, thread handoff and repeated start/stop across the ABI. No raw pointer ownership assumptions may escape undocumented.
- [ ] Run the same two-device test through the app adapter. Document exact supported device/carrier/install conditions and commit the integration.

**Exit:** One existing-app integration path reproduces the verified exchange with stated deployment permissions.

## Task 7: Add verified encrypted interoperability

**Files:** Create `docs/research/encryption.md`, `src/encryption.rs` and synthetic encryption fixtures/tests; modify capability negotiation, message processing and platform storage.

- [ ] Capture the current peer's offered and selected encrypted modes. Read GSMA RCC.16 and distinguish standards-based MLS from any legacy Google-specific mode encountered.
- [ ] Establish access to required identity/key delivery services. Provider session admission alone does not establish client-provider key-service access.
- [ ] Evaluate an existing Rust MLS implementation against the selected RCS profile; pin its revision/version and run its relevant test vectors. Do not design new cryptography.
- [ ] Implement key package publication/retrieval, conversation establishment, message encryption/decryption, persistent state and the profile's identity binding requirements.
- [ ] Test identity mismatch, missing/expired keys, reordered and replayed messages, state loss and an unsupported encrypted mode. Never silently downgrade an established encrypted conversation or falsely advertise encryption.
- [ ] Exchange encrypted text both ways with current Google Messages and verify the peer's encryption indication plus successful decryption. Verify the applicable identity confirmation procedure.
- [ ] Commit only after the negotiated encrypted mode passes; document exact scope and unresolved modes.

**Exit:** Demonstrated encrypted compatibility for the documented mode. Basic transport interoperability remains clearly distinguished from this result.

## Execution and validation

Start with Tasks 1–2. Tasks 3–4 consume their evidence, so their exact transport
patches and public signatures must be specified once the route is known. This
is intentional evidence-based sequencing: the plan does not pretend an unknown
Google authentication exchange has already been solved. Review each resulting
sub-project implementation detail against the acceptance gates above.

For each nontrivial implementation change: write the relevant failing fixture
test, confirm the failure, make the smallest fix and rerun that test. Once the
crate exists, use:

```bash
cargo fmt --check
cargo test --locked
cargo clippy --locked --all-targets -- -D warnings
```

Apply the warning policy to our code and modified paths; upstream warning cleanup
is not a prerequisite for network feasibility. Run Android build/link/device
checks for the actual host; a Linux `cargo check` does not replace them. Keep
offline tests independent of live accounts. Record live checks separately with
date, versions, provider, route, install privilege, direction and observed result.

No dependable completion date can be assigned before Task 2. Provider admission
may require carrier/OEM cooperation; no amount of protocol implementation alone
guarantees that access. If blocked, report the specific missing requirement and
keep the interoperability goal open.

Attachments, groups, reactions and broader carrier certification follow the
verified text path. Do not expand into them before the first two-way exchange.

## Sources

1. [Google: How RCS works](https://docs.jibemobile.com/intro?hl=en) — carrier and Jibe interconnection architecture, not a public independent-client enrollment API.
2. [AOSP: IMS single registration](https://source.android.com/docs/core/connect/ims-single-registration) — API surface, device requirements and permissions.
3. [Pinned upstream message dispatch](https://github.com/Hirohumi/rust-rcs-client/blob/720b42fad99d6d1f71dd89dcb11293245a0960d7/src/rcs_engine.rs) — hardcoded recipient capabilities and transport selection.
4. [Pinned upstream ICC boundary](https://github.com/Hirohumi/rust-rcs-core/blob/f2f351c467ba6f2aa9a786647845b6ad21f300c5/src/ffi/icc.rs), [GBA implementation](https://github.com/Hirohumi/rust-rcs-core/blob/f2f351c467ba6f2aa9a786647845b6ad21f300c5/src/security/gba/mod.rs) — platform limitations and sensitive debug logging.
5. [GSMA: RCC.16 encryption specification](https://www.gsma.com/solutions-and-impact/technologies/networks/gsma_resources/rcc-16-rich-communication-suite-end-to-end-encryption-specification/) — MLS-based RCS encryption.
6. [Google: Cross-platform E2EE rollout, May 11, 2026](https://blog.google/products-and-platforms/platforms/android/android-ios-end-to-end-encrypted-rcs-messaging/) — current peer requirements need investigation beyond the old APK.
7. [GSMA: RCC.07 client/network specification](https://www.gsma.com/solutions-and-impact/technologies/networks/gsma_resources/rcc-07-rich-communication-suite-advanced-communications-services-and-client-specification/), [RCC.14 provisioning](https://www.gsma.com/solutions-and-impact/technologies/networks/gsma_resources/rcc-14-service-provider-device-configuration/) — source of applicable protocol requirements; choose the actual supported profile during route discovery.
