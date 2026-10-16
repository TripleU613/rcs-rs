# Pinned upstream reuse audit

Checked 2026-10-16 on x86_64 Arch Linux, Rust 1.99.0. These projects provide
reusable protocol code, but the tested baseline does not establish Google Messages
interoperability. No HTTP/SIP request, registration, SIM authentication, or device
operation was performed during this audit.

## Source and licensing

| Project | Exact audited commit | Package | License |
| --- | --- | --- | --- |
| [rust-rcs-client](https://github.com/Hirohumi/rust-rcs-client/tree/720b42fad99d6d1f71dd89dcb11293245a0960d7) | `720b42fad99d6d1f71dd89dcb11293245a0960d7` | 0.5.4 | Apache-2.0 |
| [rust-rcs-core](https://github.com/Hirohumi/rust-rcs-core/tree/f2f351c467ba6f2aa9a786647845b6ad21f300c5) | `f2f351c467ba6f2aa9a786647845b6ad21f300c5` | 0.3.1 | Apache-2.0 |

Both manifests and LICENSE files were checked at these commits; remote HEAD still
matched each pin on the audit date. The client depends on a sibling
`../rust-rcs-core` path with version `0.3`. Keep both pins together when reusing the
source; neither checkout tracks Cargo.lock. This is not a transitive-license audit.
Sources: [client manifest](https://github.com/Hirohumi/rust-rcs-client/blob/720b42fad99d6d1f71dd89dcb11293245a0960d7/Cargo.toml),
[client license](https://github.com/Hirohumi/rust-rcs-client/blob/720b42fad99d6d1f71dd89dcb11293245a0960d7/LICENSE),
[core manifest](https://github.com/Hirohumi/rust-rcs-core/blob/f2f351c467ba6f2aa9a786647845b6ad21f300c5/Cargo.toml),
[core license](https://github.com/Hirohumi/rust-rcs-core/blob/f2f351c467ba6f2aa9a786647845b6ad21f300c5/LICENSE).

## What actually ran

Existing, unmodified sibling checkouts were reused from `/tmp/rcs-plan-nyBRBs/`.

| Offline check | Result | What it establishes |
| --- | --- | --- |
| Client `cargo test --lib --offline` | Pass, **0 tests** | Host library test target compiles/links; no behavioral coverage |
| Core `cargo test --lib --offline` | Pass, **4 tests** | Authentication-challenge parsing, random-string utility, ID generation, timer |
| Separate consumer `cargo test --offline -- --nocapture` | Pass, **4 tests**, 0 doctests | Real host linkage plus WAP parsing, context/root loading, platform-stub behavior, synthetic digest/header logging |

The consumer harness calls the public WAP parser with synthetic VERS/TOKEN XML,
checks the returned version/validity/token, constructs and drops a Context with a
public PEM root, and confirms the same valid certificate in DER form causes a
caught panic. It invokes only pure digest/header parsing and Linux stub helpers;
it never starts auto-configuration, connects HTTP/SIP, or invokes a SIM backend.
Context workers wait for requests; no request is submitted. No packet-level
network trace was collected.

Private harness source, resolved lockfile, and logs are outside this repository:
`/home/tripleu/Downloads/pixel4a-geekbox/rcs-gapps-re/upstream-evaluation/`.
The upstream client/core emitted 133/87 compiler warnings respectively; a green
test command is not a clean lint audit. Source trees and application code were
not patched to make these checks pass.

## Concrete blockers before real credentials

**Debug builds expose secrets.** `platform_log` writes to stdout on this host and
to the platform logger on supported mobile targets; its release implementation
is empty. The offline harness confirmed that digest generation logs a synthetic
username and hex-encoded password, and response parsing logs a synthetic
Set-Cookie value. These are observed leaks, not hypothetical Debug formatting.
Sources: [logger](https://github.com/Hirohumi/rust-rcs-core/blob/f2f351c467ba6f2aa9a786647845b6ad21f300c5/src/ffi/log.rs#L21-L57),
[digest](https://github.com/Hirohumi/rust-rcs-core/blob/f2f351c467ba6f2aa9a786647845b6ad21f300c5/src/security/authentication/digest.rs#L317-L386),
[response headers](https://github.com/Hirohumi/rust-rcs-core/blob/f2f351c467ba6f2aa9a786647845b6ad21f300c5/src/http/response.rs#L60-L71).

Additional source-only findings on paths that were **not executed**:

- The HTTP writer logs the serialized request, including query and headers.
  The response reader logs transferred body chunks. ACS configuration therefore
  risks exposing request identifiers/tokens, cookies, and returned credentials.
  [Request writer](https://github.com/Hirohumi/rust-rcs-core/blob/f2f351c467ba6f2aa9a786647845b6ad21f300c5/src/http/mod.rs#L935-L948),
  [body reader](https://github.com/Hirohumi/rust-rcs-core/blob/f2f351c467ba6f2aa9a786647845b6ad21f300c5/src/http/response.rs#L623-L629).
- The ACS layer logs full successful configuration XML; the C entry point logs
  returned IMS/RCS application configuration. SIM AKA logs RES, CK, IK and AUTS;
  GBA logs the derived K_s_NAF. SIP receive logs raw wire chunks, including any
  credentials or bodies they contain.
  [ACS](https://github.com/Hirohumi/rust-rcs-client/blob/720b42fad99d6d1f71dd89dcb11293245a0960d7/src/provisioning/device_configuration.rs#L444-L458),
  [configuration callback](https://github.com/Hirohumi/rust-rcs-client/blob/720b42fad99d6d1f71dd89dcb11293245a0960d7/src/lib.rs#L420-L440),
  [AKA](https://github.com/Hirohumi/rust-rcs-core/blob/f2f351c467ba6f2aa9a786647845b6ad21f300c5/src/security/aka/mod.rs#L164-L207),
  [GBA](https://github.com/Hirohumi/rust-rcs-core/blob/f2f351c467ba6f2aa9a786647845b6ad21f300c5/src/security/gba/mod.rs#L595-L605),
  [SIP](https://github.com/Hirohumi/rust-rcs-core/blob/f2f351c467ba6f2aa9a786647845b6ad21f300c5/src/sip/sip_transport.rs#L114-L125).

**Host TLS is real, but its root loader needs a fix.** It builds a normal rustls
ClientConfig with supplied roots and no client certificate; this audit did not
find a bypass verifier on that path. It starts with an empty root store and
loads from `<root>/certs`, rather than automatically loading system roots. The
DER branch initializes a vector with 4096 zero bytes before appending the file,
then unwraps certificate insertion. The consumer harness reproduced
`InvalidCertificate(BadEncoding)` with a valid public DER certificate; the PEM
path constructed successfully. No TLS handshake or Android TLS implementation
was tested. [Root loader](https://github.com/Hirohumi/rust-rcs-client/blob/720b42fad99d6d1f71dd89dcb11293245a0960d7/src/context.rs#L132-L211),
[host TLS construction](https://github.com/Hirohumi/rust-rcs-core/blob/f2f351c467ba6f2aa9a786647845b6ad21f300c5/src/io/network/stream.rs#L113-L134).

**Default Linux platform support is incomplete.** The harness confirmed that
ICC opening and active-network lookup return None and active DNS servers are
empty. HTTP domain resolution obtains that platform DNS list. Mobile builds
instead require actual native ICC/AKA/network/socket implementations; a host
build with the `android` feature is not an Android integration test because
these branches also check the target OS.
[ICC stubs](https://github.com/Hirohumi/rust-rcs-core/blob/f2f351c467ba6f2aa9a786647845b6ad21f300c5/src/ffi/icc.rs#L52-L77),
[network helpers](https://github.com/Hirohumi/rust-rcs-core/blob/f2f351c467ba6f2aa9a786647845b6ad21f300c5/src/ffi/net_ctrl.rs#L176-L267),
[HTTP DNS path](https://github.com/Hirohumi/rust-rcs-core/blob/f2f351c467ba6f2aa9a786647845b6ad21f300c5/src/http/mod.rs#L231-L244).

## Minimum reuse path

1. Retain both exact source pins and Apache notices. Reuse the WAP parser first;
   the consumer harness demonstrates that useful host path without a new facade.
2. Remove or redact the sensitive logging call sites before loading genuine
   configuration or credentials. Release logging suppression alone leaves debug
   integrations exposed. Add synthetic assertions for the exercised leaks.
3. Fix DER reading to start with an empty vector and return root-loading errors;
   provide explicit usable trust roots and a real host DNS seam. Supply actual
   mobile platform implementations before treating mobile linkage as usable.
4. Keep the independently recovered Google bootstrap/admission work separate
   until it yields usable provisioning. The upstream request builder hardcodes
   UP_2.4/RCS 11.0 and its default user agent reports a fixed device/client.
   A bounded source search found no DroidGuard, MobileConfiguration,
   PhoneDeviceVerification, or selected TS43 flow identifiers. Those admission
   paths cannot be assumed to exist upstream.
   [ACS request builder](https://github.com/Hirohumi/rust-rcs-client/blob/720b42fad99d6d1f71dd89dcb11293245a0960d7/src/provisioning/device_configuration.rs#L391-L395),
   [default user agent](https://github.com/Hirohumi/rust-rcs-core/blob/f2f351c467ba6f2aa9a786647845b6ad21f300c5/src/http/request.rs#L40-L55).
5. After obtaining genuine configuration, test its parser/registration settings
   offline, then establish actual SIP/MSRP behavior and a Google Messages RCS
   send/reply. Neither current test counts nor upstream functionality claims
   establish that result. Upstream itself lists standalone CPM/HTTP-file-transfer
   limits and untested SIP-session/MSRP work.
   [Client scope](https://github.com/Hirohumi/rust-rcs-client/blob/720b42fad99d6d1f71dd89dcb11293245a0960d7/README.md),
   [core caveats](https://github.com/Hirohumi/rust-rcs-core/blob/f2f351c467ba6f2aa9a786647845b6ad21f300c5/README.md).

This was a bounded baseline and credential-handling audit, not a complete
security, protocol-conformance, or dependency audit. Upstream source was not
imported into rcs-rs, and no interoperability claim follows from these checks.

## Local evaluation fixes

The [portable patch set](../../patches/upstream/README.md) applies to the pins
above. It suppresses the shared protocol logger in debug/release/mobile builds,
fixes DER/PEM trust loading with fallible Context/C-constructor propagation, and
rejects truncated WAP documents at the shared reader and cache callers. Synthetic
sentinel logging, root-loading and XML regressions were observed failing before
fixes and passing afterward. No private configuration was used in these tests.

The client pins quick-xml to 0.37.5 to get parser-level unfinished-tag detection;
root attributes are checked and nested parse errors reach callers. Review caught
whitespace/trimmed-reader and empty-root gaps in the first delimiter check; three
regressions reproduced them before the parser upgrade and pass afterward.

Patched results: core 6 functional tests, client 14 tests, external consumer
4 tests pass. The consumer now constructs both PEM and DER contexts successfully
and still confirms that Linux SIM/network helpers are stubs. Full core testing
also exposed one existing failing doctest in
`internet::syntax::index_skipping_ows_and_obs_fold` (trailing-newline fixture
mismatch); it reproduces on the unmodified pin. The other 10 core doctests pass.
Upstream warnings remain; no clean lint or complete security audit is claimed.

Patch application is tested from clean pinned checkouts, including the binary
DER fixture. Upstream source is not bulk-vendored or wired into the root crate.
Upstream Android callback linkage, live TLS, valid carrier configuration, SIP
registration and RCS delivery remain unverified. USB system-file reads failed,
but subsequent wireless pairing delivered valid installed telephony, connectivity
and permission-controller artifacts. The separate [ordinary-client platform
audit](ordinary-client.md#installed-platform-audit-and-ims-transport--2026-10-16)
records their exact permission branches and live network observations. Active
IMS requests were denied, passive observation/socket marking succeeded, and the
IMS-bound proxy send failed with ENETUNREACH. Default DNS returned only IPv4 and
observed IMS base-link addresses were IPv6; translation/native routing/policy
remain uninspected, so the underlying cause is unresolved.
That probe does not supply working upstream network callbacks or SIM authority.
