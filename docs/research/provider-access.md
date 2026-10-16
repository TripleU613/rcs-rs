# Access to the test subscription

Checked 2026-10-16. There is no independently admitted RCS session yet. A controlled
discovery comparison corrected the earlier conclusion that UPI was the only
available route: supplying the actual installed GMS version enables direct TS43
carrier authentication. That route does not require Google's UPI number token.
The newest direct ACS test still returned an invalid configuration without
subscriber credentials. UPI verification remains throttled separately.
The user confirmed this exact line has never previously activated RCS on a
stock phone. There is therefore no positive reference activation for this line;
subscription/environment admission and remaining protocol differences are still
separate unknowns.

Current Messages includes its own package/version and installed GMS
package/version in discovery. Holding the request's other fields constant,
omitting GMS returned UPI disabled (wire 1), direct TS43 disabled and policy
`upi-mo-strict-policy-mt-priority`; adding the installed compatible implementation's
actual version returned UPI without ACS fallback (wire 3), direct TS43 enabled,
a carrier entitlement endpoint and policy `upi-carrier-tos-ts43`. Policy comes
from a separate type-3 configuration: response oneof field 5, inner string field
1. UPI and legacy request builders copy it verbatim to
`supported_provisioning_types`; the direct TS43 builders omit that header.
It cannot be inferred from the UPI enum. Both comparisons held GSF ID at zero, so they establish the
effect of package context, not complete native-client parity.
The actual Messages-context GServices ID was subsequently recovered without
changing identity. Using it versus zero returned identical onboarding payloads
and policy, with differing cache validity and root experiment-assignment IDs.
The traced experiment-ID consumer registers them with Phenotype, without a
direct ACS consumer. Rust now accepts the actual ID through
`Probe::with_gsf_android_id`.

The original Messages route selector checks direct TS43 before UPI, but also
requires local GMS availability at version 254500000. The installed microG
version is below that local threshold. Our independent carrier adapter can
perform genuine selected-SIM authentication without claiming that the app's
local Google SDK gate passed. See [the direct-route evidence](gapps-bootstrap.md#9-direct-ts43-to-acs-path).

A read-only native check now confirms that gate returns status 2 (update
required). Messages selects external Carrier Services, has RCS switched on,
and displays “Connecting…”. Its provisioning worker is idle in `RetryState`;
the saved next attempt is **2026-10-17 07:33:36 UTC**. This is a client schedule,
not a recovered server quota-reset time. The cached configuration has version
0, validity 0 and no ACS token or MLS configuration. Native route flags and
SIM/device metadata match our independent probe. See
[the native baseline](gapps-bootstrap.md#14-native-activation-state-and-local-sdk-gates).

## Current gates

| Stage | Evidence | Remaining requirement |
| --- | --- | --- |
| Configuration discovery | Corrected Rust request receives ACS, direct TS43 support and a carrier endpoint | Include actual installed GMS context; preserve route-specific policy |
| Native Messages baseline | RCS enabled, retry scheduled, external Carrier Services selected; direct GMS check returns update-required | The installed microG lacks the Constellation and direct entitlement service implementations; native activation is not a positive control |
| Native Constellation admission | Actual Messages-context broker request for service155 returns API_DISABLED (23), no service binder | Implement the missing platform API or continue the independent Rust path; no verification transaction was sent by this check |
| Direct carrier-to-ACS route | Fresh carrier authentication/token, genuine platform proof and owned participant signature reach ACS | Resolve version-0 invalid config and obtain accepted subscriber credentials |
| Direct request parity | Native binding map/proof bytes/query assembly match; extra policy header removed in attempt06 | Corrected request still gets unspecified invalid config; no positive attestation verdict |
| Network-path comparison | Direct ACS over selected-SIM cellular also returns invalid config | A different egress did not resolve this tested request |
| Legacy IMSI route | Source-backed minimal-profile request reaches ACS from host but receives invalid config | Resolve admission; cellular timeouts alone were inconclusive |
| Explicit-number diagnostic | Supported legacy MSISDN request with the SIM's own number also gets invalid config | This was a separate experiment, not an observed fallback after version 0 |
| GMS consent and initial verification | Rust consent works; an earlier probe received a real pending TS43 challenge | A fresh, non-throttled verification challenge |
| Carrier authentication | Actual selected-SIM EAP-AKA and AcquireTemporaryToken succeeded | Submit complete genuine JSON under the corrected `joty` string field 2 |
| Read-only number status | Signed reference query at 14:39 UTC and exported Rust API at 14:47 UTC succeeded with zero records | This lookup cannot create a verified number or restore a challenge |
| Google number credential | Last Rust Sync at 14:30 UTC returned NONE / THROTTLED / record code 8 | Successful verification and its returned number credential |
| UPI ACS provisioning | Current Messages consumer path recovered statically below | A genuine Google number credential, matching attestation/session and accepted subscriber configuration |
| Registration and messaging | No independent service session | Register using the accepted configuration, then verify a two-device RCS send/reply |

The failed historical Proceed used the wrong carrier JSON tag. The corrected
Rust request has synthetic wire/transport coverage and independent descriptor
review, but the server throttle prevented its fresh live test. No quota reset
deadline was recovered. The timestamp pair yields no positive retry duration;
Messages' client backoff does not establish when the server will admit another
attempt. A single further attempt at 08:08 UTC, after more than 65 minutes
since the previous one, returned the same throttle. It issued no challenge or
number credential, so carrier authentication, corrected Proceed and the prepared
UPI ACS handoff were not run. The one-shot research job is terminal; no further
research verification attempts are scheduled. Messages retains its own delayed
provisioning worker. Temporary debugging was removed and USB retained. Do not
reset IID/SIM identities or repeatedly submit verification to turn this unknown
into apparent progress.

A user-resumed same-identity attempt at **14:30 UTC**, after more than six hours,
returned the same verification throttle. No carrier authentication or Proceed
ran, and no more research Sync attempts are scheduled. The old challenge is not a normal
resume path: GMS stops continuation after a successful RPC returns NONE/FAILED;
its exception path alone preserves the previous pending record. Its server TTL
and post-failure reuse policy remain unknown.

The separate read-only `PhoneNumber/GetVerifiedPhoneNumbers` path cannot restore
pending challenges. Its original default uses project `745476177629`, sharing
the full-flow RSA identity but using a distinct token. Unlike unsigned bootstrap
Sync, it enables a persisted-EC-key signature by default, without an ack gate.
The historical unsigned read probes did not establish parity with that default.
A signed query at **14:36 UTC**, using our existing owned tokens/key and RCS
selection, returned outer gRPC 8 with structured `RATE_LIMIT_EXCEEDED` for the
**project-wide read requests/minute** limit, value 1,350,000, location global.
This is distinct from Sync's record-level verification-attempt throttle and
does not establish later authentication acceptance. No verified records were
obtained on that request. A single recheck after more than 125 seconds returned
**gRPC 0 with zero records**, using the same owned identity/key and a fresh
timestamp/session. The exported Rust API independently repeated the accepted
empty read at 14:47 UTC. The signed read path is now accepted independently of the
still-throttled Sync. It cannot create the missing credential. See the source and
capture boundaries in
[the bootstrap evidence](gapps-bootstrap.md).

## The UPI credential goes to a different ACS endpoint

The number credential is a Param named `id_token` in Verification repeated
field 6 (`jowc`: name 1, value 2). Original GMS `bqzr.q` copies these to the
callback Bundle; `braf.d` removes `id_token` and assigns the public verification
result's credential. It does not validate the token's claims. Wire VERIFIED
state 3 and a nonempty verified-info phone are separate success checks.

Verified-info (`joxh`, Verification oneof field 3) has phone string 1,
verification timestamp 2 and method enum 6. It does not contain this credential
or an identified expiry. Sync's separate field-5 token records belong to a
restoration mechanism, and Proceed has no corresponding root token list.
The Rust accessor reads only the named Verification parameter, rejects duplicate
or malformed credential entries and omits it from Debug. It does not convert
unvalidated token presence into a verified/ready state.

Current Messages build 324451063 follows this static chain:

1. `ejwu.D/E` accepts the successful phone-verification result and caches the
   returned number credential under a SIM-specific `msisdn_token_for_sim_` key.
2. `ejvn.k` requests the ACS base endpoint with
   `client_authenticity_support=goog-mls-upi`, keeping the logical provisioning
   session and selected SIM. The response supplies cookies and an attestation
   nonce; `ejvn.C` passes the cached number credential to `ejvy.C`.
3. `ejvy.C` posts to **`/provision`**, with the credential in the
   **`rcs_msisdn_token` header**. `ejuo.a` sets `Content-Type: text/plain` and
   sends padded standard Base64, without line breaks, of the `fzai` protobuf.

This is separate from the direct-TS43 multipart route. Do not put the carrier's
temporary token in `rcs_msisdn_token`. The normal UPI metadata query is assembled
by `ekcb.f`; it does not automatically add the direct route's empty `token` or
`SMS_port` query parameters.

`fzai` contains eligibility enum field 1 (`ELIGIBLE=1`) and attestation submessage
`fzaa` in field 2. In this path `ejtc.m` selects **binding version 1**; a log
label containing V2 does not change the actual protobuf version.

| `fzaa` field | Value |
| --- | --- |
| 1 | Binding version, int32 |
| 2 | Genuine `rcs_provisioning` DroidGuard result |
| 3 | Random salt |
| 4, 5 | Actual IMSI and IMEI, when nonempty |
| 6 | MSISDN when supplied; this UPI builder leaves it empty |
| 7 | Google verified-number credential |
| 8 | Actual `JIBE_ACS_COOKIE` value |
| 9 | GMS-context IID token when nonempty |
| 10 | Logical provisioning session when present |

For version 1, the DroidGuard map hashes each populated binding value as
lowercase hex SHA-384 of UTF-8 `value + salt`; `APP_NAME` remains the application
name. Its session binding matches `rcs_engine_session_id`. Version-2-only map
keys and the carrier temporary token do not belong in this version-1 proof.
The optional GMS IID header, ordinary client headers and supported provisioning
types still follow the selected configuration.

The two session UUIDs have distinct owners. Rust's `InitialSync.caller_session_id`
must carry the logical client provisioning session: it supplies the verification
`session_id` parameter and nonce hash, then ACS `rcs_engine_session_id` and
DroidGuard `PROVISIONING_SESSION_ID`. `InitialSync.session_id` is the separate
GMS/PDV RPC session, reused for Proceed. Original GMS generates that second UUID
internally. Do not substitute it for the caller's logical ACS session.
This establishes the request correlation; it does not establish signed response
token claims. Sources: `ejwu:240-256`, `ejvy:81-92`, `dmot:36-37`,
`ejtc:168-172`, `brag:302`, `bqym:60`, `brdw:1148-1152`.

When the cached ACS nonce is available, `ejvy.k` also schedules the actual MLS
participant-key proof and adds its query parameters; it then clears that nonce.
Absence of a nonce has a fallback branch, but static reachability does not prove
that the backend accepts that branch for this subscription.

The bounded cache readers (`ekao.g`, `ejvy.I`) check presence/nonemptiness. No JWT
expiry or audience validation was found in this consumer path. That does not
establish any signed credential's lifetime or replace server acceptance. An ACS
HTTP 200 still requires configuration validation before registration.

Private source evidence: `constellation-static/ejwu.java.txt`,
`ejtc.java.txt`, `ejuo.java.txt`, `ejvv.java.txt`, and
`messages-static/defpackage.{ejvn,ejvy,ejsy,fzaa,fzai,ekao}.java.txt`.
The field map is checked against generated descriptors and their setters, not
inferred from member order. The private summary is
`constellation-static/upi-credential-acs-consumer-groundtruth.json`.
There is no successful live UPI provisioning capture yet.

## Rust probe implementation

`AcsSession::upi_challenge(&UpiParameters)` requests `goog-mls-upi`, captures the
nonce/cookie and generates a fresh UUID salt. The caller supplies actual client
metadata, full selected-SIM/device identifiers, logical caller session, policy,
eligibility and number credential. Client metadata must already match the
selected configuration's formatting. This bounded implementation does not
support alternate carrier identifier encodings.

The returned context provides `private_droidguard_inputs()` for a genuine
`rcs_provisioning` platform call and `private_mls_signing_input()` for an owned
participant key. Its `provision` method accepts that platform result and a
P-256 SPKI public key/DER ECDSA signature, verifies the signature against the
exact nonce, then consumes the context to send one POST. MLS signature framing
uses [RFC 9420 SignWithLabel](https://www.rfc-editor.org/rfc/rfc9420.html#section-5.1.2).
The retained native synthetic reference independently verifies with OpenSSL and
matches those signing bytes; this does not establish backend acceptance.

One active exchange per `AcsSession` prevents concurrent responses from pairing
one nonce with another cookie. Overlapping challenge calls fail explicitly; drop
the context to cancel it. The POST also pins the cookie header used by the proof.
Tests cover this capture-time exclusion and a later cookie-jar rotation, invalid
signatures/inputs, exact independent protobuf/hash fixtures, redirect rejection
and service retry reporting. The code never retries automatically.

Eligibility is an explicit input: unspecified 0, eligible 1, ineligible 2,
denied 3. Messages reads this per-SIM cached value and updates it from verification
status; the builder must not infer it merely from nonempty token text. Zero and
optional IID omission are retained in the wire format. Size caps are local
resource limits, not recovered server-advertised maxima.

A separate live request during this pass returned HTTP 200 with method
`goog-mls-upi`, a 36-byte nonce and `JIBE_ACS_COOKIE`. It sent no number credential
and made no verification RPC. Private evidence is in
`constellation-static/upi-challenge-attempt01/`. The Rust credential-bearing POST
has only local coverage until Google number verification supplies a genuine
credential. DroidGuard generation, participant-key persistence, alternate MLS
suites, subscription-change cancellation and accepted configuration validation
remain host/integration work. The application name is caller-supplied; the
reference client uses Google Messages, and admission of another app is unproven.

## Android host requirements on this phone

Read-only USB inventory found the normal telephony/IMS feature, but no advertised
IMS single-registration feature. The platform reports:

| Query | Result |
| --- | --- |
| `cmd phone src get-test-enabled` | false |
| `cmd phone src get-device-enabled` | false |
| `cmd phone src get-carrier-enabled -s 0` | false |
| `cmd phone ims get-ims-service -s 0 -d` | `org.codeaurora.ims` |
| `cmd phone ims get-ims-service -s 0 -c` | empty |
| Current default SMS application | Google Messages |

The feature-validation override getter threw a null-unboxing exception. It did
not return a capability result: upstream `RcsProvisioningMonitor` represents an
unset override as nullable Boolean, while `PhoneInterfaceManager` returns a
primitive boolean. No IMS setters, carrier overrides or role changes were used.

Android requires device support and privileged/default-SMS access for its single
registration APIs. A normal SMS role is therefore insufficient, and enabling a
test override would not establish real vendor support. See the
[AOSP single-registration requirements](https://source.android.com/docs/core/connect/ims-single-registration).

SIM authentication also has a platform permission boundary. The subsequent
[installed-code and ordinary-UID audit](ordinary-client.md#installed-platform-audit-and-ims-transport--2026-10-16)
establishes that this build checks the ICC-specific app-op, then `USE_ICC_AUTH`
or selected-sub carrier privilege, then `READ_PRIVILEGED_PHONE_STATE` or carrier
privilege. Its method has no feature-flag conditional and retains the last
fallback despite the newer API documentation. The installed SMS role's identifier
app-op is not an ICC grant; its extra single-registration permissions are granted
only to system packages. Actual SMS-role enrollment remains untested.

The ordinary APK satisfied no ICC branch. Active restricted IMS requests threw
`SecurityException`, while passive observation and unused socket binding worked.
Default DNS returned only IPv4 for the configured carrier proxy; that IMS-bound
send failed with `ENETUNREACH`. Stacked links/translation remain uninspected.
Later use of an advertised IPv6 P-CSCF from a laboratory system capture yielded
real403/401 SIP responses and a socket mark matching IMS. A contact-free REGISTER
query offered MD5/`auth-init`; the Rust-generated response with the configuration's
APPAUTH credentials received403/`user_unknown`. No binding or admitted session
was obtained. Later reference-source inspection showed that its parser reads
those APPAUTH credentials only for Digest, while this profile selects AKA.
The static-password test therefore did not exercise its proper AKA route.
Registrar choice, line enrollment and ordinary-app proxy discovery remain
unresolved; this result does not validate the supplied password or AKA.
The earlier successful SIM-auth laboratory exchange used the
privileged Phone process through temporary root instrumentation; it does not
prove an ordinary app can perform that operation. Host integration must check
actual access and return an explicit failure when unavailable.
Sources: Android 17 [TelephonyManager](https://android.googlesource.com/platform/frameworks/base/+/refs/heads/android17-release/telephony/java/android/telephony/TelephonyManager.java)
and [permission definitions](https://android.googlesource.com/platform/frameworks/base/+/refs/heads/android17-release/core/res/AndroidManifest.xml).

Private read-only captures are under `runtime/platform-*`; downloaded Android 17
source is under `runtime/platform-source/`. Source explains the upstream API;
the installed build's returned values remain the authority for this inventory.
