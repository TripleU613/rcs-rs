# Access to the test subscription

Checked 2026-10-16. The selected route remains Google UPI number verification,
followed by the UPI ACS provisioning path. There is no independently admitted RCS
session yet. Carrier authentication succeeds, but its temporary token alone is
not the Google verified-number credential needed by this route.

## Current gates

| Stage | Evidence | Remaining requirement |
| --- | --- | --- |
| Configuration discovery | Rust receives this subscription's ACS and UPI configuration | Preserve the configured route and actual client metadata |
| GMS consent and initial verification | Rust consent works; an earlier probe received a real pending TS43 challenge | A fresh, non-throttled verification challenge |
| Carrier authentication | Actual selected-SIM EAP-AKA and AcquireTemporaryToken succeeded | Submit complete genuine JSON under the corrected `joty` string field 2 |
| Google number credential | Last Rust Sync at 07:02:33 UTC returned NONE / THROTTLED / record code 8 | Successful verification and its returned number credential |
| UPI ACS provisioning | Current Messages consumer path recovered statically below | A genuine Google number credential, matching attestation/session and accepted subscriber configuration |
| Registration and messaging | No independent service session | Register using the accepted configuration, then verify a two-device RCS send/reply |

The failed historical Proceed used the wrong carrier JSON tag. The corrected
Rust request has synthetic wire/transport coverage and independent descriptor
review, but the server throttle prevented its fresh live test. No quota reset
deadline was recovered. The timestamp pair yields no positive retry duration;
Messages' client backoff does not establish when the server will admit another
attempt. Do not reset IID/SIM identities or repeatedly submit verification to
turn this unknown into apparent progress.

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

This is not the disabled direct-TS43 multipart route. Do not put the carrier's
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

SIM authentication also has a platform permission boundary. Android 17 source
introduces feature-flagged `USE_ICC_AUTH` (`signature|privileged`) alongside
carrier-privilege and `USE_ICC_AUTH_WITH_DEVICE_IDENTIFIER` access. Its new API
documentation retires `READ_PRIVILEGED_PHONE_STATE` for this operation. Both ICC
permission names exist on the installed build, but this inventory does not
establish its active flag/enforcement path. The successful laboratory exchange
used the privileged Phone process through temporary root instrumentation; it
does not prove an ordinary app can perform that operation. Host integration must
check actual access and return an explicit failure when unavailable.
Sources: Android 17 [TelephonyManager](https://android.googlesource.com/platform/frameworks/base/+/refs/heads/android17-release/telephony/java/android/telephony/TelephonyManager.java)
and [permission definitions](https://android.googlesource.com/platform/frameworks/base/+/refs/heads/android17-release/core/res/AndroidManifest.xml).

Private read-only captures are under `runtime/platform-*`; downloaded Android 17
source is under `runtime/platform-source/`. Source explains the upstream API;
the installed build's returned values remain the authority for this inventory.
