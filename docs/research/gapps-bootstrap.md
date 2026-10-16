# GApps RCS bootstrap: recovered behavior

Investigation date: 2026-10-16. Status: bootstrap discovery, ACS challenge,
consent lookup, a verification challenge and carrier SIM authentication have been reproduced;
subscriber provisioning, registration and message exchange
remain incomplete. Findings distinguish static code from execution.

## Artifact identity

| Artifact | Version | SHA-256 | REA package evidence |
| --- | --- | --- | --- |
| Messages reference, old | 151793063 / 20220926 | `9238cb2d0da0cea7926f6d18d089a582f34f3a645d38f2049a22e0bd0bff31a2` | `ev_6ac5740146d3f47bcb7cd1253c03d0c8bae65485c1f6bdb89b621183fc3c4fda` |
| Messages reference, current | 324451063 / 20261002 | `2f666c55f129da84e1606d06e183ee08faf2b560d5a53cb44835007b4a97b159` | `ev_20f422379c37900f1f5efa6c6699f70025397f42b9e5a10f47b11d4c9b70a03e` |
| Carrier Services | 31153903 / 20250826 | `9072f0f010132757f0efa5ad759269667ed2c982633204c01ba4e48c71eecee4` | `ev_b27d8495dec76b0fbff43cb62d7998d3c6db34e969ddd31f3539340f1c879069` |
| Original Google Play Services, offline backup | 263737035 / 26.37.37 | See private package evidence | `ev_14557c45416b3080baabcd6400fa2288843c2e7ffedfdab9fda669d7dce74574` |

The installed Play Services implementation during live tests is microG. Original
Google Play Services was inspected offline from the existing backup; it was not
restored to the phone. APKs, private traces and credentials remain outside Git.

## 1. Configuration discovery works independently

**Observed live:** an independent host request returned HTTP/2 200 with
`grpc-status: 0` and a 388-byte protobuf response (393-byte gRPC frame).
The repository Rust implementation independently repeated discovery successfully,
returning the same ACS and selected flags. Twenty-four offline tests cover request
fixtures, unknown response bytes, validation, real localhost HTTP2/gRPC trailers,
backoff reporting without automatic retries and diagnostic redaction.

```text
Authority: mobileconfiguration-pa.googleapis.com:443
Method: google.internal.communications.mobileconfiguration.v1.MobileConfigurationService/GetConfiguration
```

The request supplied the reference application's API key, package name and
certificate metadata. It did not supply Google-account OAuth, a phone number,
full IMSI, IMEI or an IMSI prefix. The GSF Android ID was zero, which the
reference code explicitly supports. This proves the observed metadata can fetch
carrier configuration; it does not establish unrestricted admission for every
third-party application or grant RCS subscriber credentials.

Request shape recovered from `elll`, `elml`, `ellt`, `ellk`, `ddmh`, `gedt` and
related protobuf classes:

```text
GetConfigurationRequest
  1: context
       1: request UUID (string)
       2: GSF Android ID (int64)
  2: repeated parameters
       1: request-local correlation ID (string)
       2: configuration type (1 = RCS onboarding)
       3: device (device name, manufacturer, form factor)
       4: carrier (MCC, MNC, optional carrier attributes)
       6: repeated package name/version pairs
```

The default OAuth flag is false. Static client construction uses an API key in
that case and adds `X-Android-Package` and `X-Android-Cert`. Certificate selection
uses the first entry in signing-certificate history, which differs from the
current signer for this artifact. No API key belongs in the source repository.

For the tested MCC/MNC, the actual response selected:

| Field | Observed value |
| --- | --- |
| ACS | `rcs-acs-tmo-us.jibe.google.com` |
| RCS enabled state | Enabled (raw enum 1) |
| Skip header enrichment | true |
| RCS profile/version | `UP_T` / `5.1B` |
| IMEI/IMSI format | Ignored (raw enum 4) |
| DroidGuard with HTTP GET | true |

Raw PII enum values must not be confused with the old client's internal format
integers. In the current artifact, `geef.c(4)` maps to enum representation 6,
`PII_FORMAT_IGNORED`. The later `ejuz` call chain nevertheless maps this
representation to sending full identifiers. The enum label alone establishes
neither omission nor a server requirement for full identifiers.

Response shape: field 1 repeats configurations; each configuration has its
correlation ID in field 1, validity duration in field 2 and onboarding flags in
oneof field 3. Onboarding ACS is oneof field 2 (direct hostname) or field 3
(MCC URL format). The server also returned fields absent from this client
schema; they must not be mislabelled or treated as a decode failure.

## 2. Google ACS issues an actual challenge

**Observed live:** a separate HTTPS GET to the discovered ACS with terminal and
client metadata and `client_authenticity_support=goog-droidguard` returned:

```text
HTTP 200
Content-Type: application/vnd.gsma.cfg-clientauth+xml; charset=utf-8
Root: {urn:gsma:params:xml:ns:cfg:clientauth:req}client-authenticity-request
Method: goog-droidguard
Fields: nonce, method id, challenge parameter
```

This request also omitted a phone number, IMSI and IMEI. The nonce, challenge
and session cookie were retained privately. The repository Rust ACS client also
completed this initial exchange live and retained its cookie in the session.
Offline checks exercise cookie scoping, redirects, error backoff, streamed body
limits and XML namespace/duplicate/missing-field handling. Receiving this document establishes
the challenge step, not successful attestation, subscriber verification or
provisioning. An HTTP 200 body of this type is not a WAP provisioning document.

Static code agrees: `ejts.j` requests this method, `ejzs` parses the nonce and
method data, and `ejts.i` stores them for subsequent states. Newer request
attestation paths also advertise `goog-mls-upi` and
`goog-mls-config-refresh` (`ejvn.k`); those were not exercised live.

## 3. The old carrier error is a local bootstrap failure

**Observed live, old build:** no ACS was supplied by the configuration provider.
`bdne.b`/`bdsf.f` produced `DISABLED_VIA_GSERVICES` before contacting a server.
The primary and application-suffixed Phenotype namespaces both returned no rows.

The local ACS selector prefers a developer override, then a configured ACS,
then an MCC template, then a gated standard hostname. Relevant namespace:
`com.google.android.ims.library`; relevant prefix: `RcsFlags__`.

A backed-up, temporary override to the standard carrier hostname moved the app
to `CARRIER_SETUP_PENDING` and produced a real HTTP 400. `bdks.b` explains this:
header enrichment sends the bare ACS URL, without the normal query builder.
The endpoint's bare-request error requires terminal/subscriber parameters. The
recovered current configuration's `skip_header_enrichment=true` is therefore
material to this flow.

An experimental in-memory state-selection hook crashed the old RCS process
because its return value was incompatible with the expected type. That run
does not establish anything about server acceptance. The app was restarted and
the temporary debug preferences and persisted ACS override were removed.

## 4. Current phone blocker: Constellation token acquisition

The verified 2026 Messages splits were installed while preserving app data and
retaining backups. **Observed live at 01:08 EDT:**

```text
Using config server URL from ddml
EnabledState -> CheckPreconditionsState -> InProgressState -> ReadyState
dedm: C11N token request failed. Returning empty optional.
Constellation.API: API_DISABLED
RetryState
```

The missing operation is precisely service 155, Binder transaction 4,
`get_iid_token` feature version 1. `dedl` requests project `466216207879`.
The real GMS implementation obtains a legacy IID/GCM registration token in its
own GMS application context, scope `GCM`. This request contains no phone number.

Number verification is a separate transaction 3 (`verify_phone_number` v2).
Its request contains a policy ID, certificate/nonce and RCS consent metadata;
field 1 must not be mistaken for the phone number. Original GMS code resolves
`phonedeviceverification-pa.googleapis.com:443` and PhoneDeviceVerification
and PhoneNumber RPC families. Those RPCs were not exercised live.

**Observed live:** existing microG `RegisterRequest` machinery, using its own
GMS context and check-in, obtained a Google-issued registration token for the
requested project. This probe did not overwrite microG's cached registrations.
The token is private. A bounded in-memory diagnostic supplied this genuine
token to `dedm.a`; the app moved from `ReadyState` to `VerifyMsisdnState`.
That establishes progress past the local token gate, not server acceptance or
equivalence to every legacy IID field. The separate `verifyPhoneNumber` call
then failed locally with `API_DISABLED`; the current app reported that fallback
to non-UPI provisioning is removed. The request's observed policy was
`upi-carrier-tos-ts43`, mode 0, boolean flag true, with one IMSI request. An unmerged
microG fork is a reference only; it was not installed or trusted as evidence of
interoperability. No ACS attestation rejection has been established.

A separate read-only `PhoneNumber/GetVerifiedPhoneNumbers` probe used microG's
already-existing own-GMS token for project `745476177629`, reference static
application metadata and fresh caller nonce. It omitted client signature and
DroidGuard. The gateway returned gRPC `PERMISSION_DENIED` with an Android-client
admission error; no verified records or JWT were obtained. That result does not
establish a requirement for either omitted field because admission failed first.
The first probe used the current signer incorrectly. Original GMS's shipped
certificate accessor uses the oldest signer; after correcting that header from
verified APK lineage, a second probe passed application admission but returned
gRPC `INVALID_ARGUMENT`: `could not verify iid_token`. A generic Google-issued
GCM registration therefore cannot be assumed to satisfy the backend's legacy
IID validation. The key-bound registration protocol remains under investigation;
optional `X-Goog-Spatula` metadata has not yet been exercised.

Original GMS's current registration path adds `X-appid`, an 11-character IID
from SHA-1 of its RSA public key: adjust byte 0 to `(byte & 15) + 112`, then
Base64URL-encode the first eight bytes without padding. Exact DEX scans found
no `pub2` literal in the inspected base or Dynamite A/C splits; that fork's
additional registration hypothesis is not established by this artifact. The
separate ECDSA client key is advertised by the first Sync/GetConsent header,
then used for client authentication after backend acknowledgement.

## 5. Full-flow consent lookup works independently

**Observed live:** `PhoneDeviceVerification/GetConsent` returned HTTP/2 200,
gRPC status 0 and a 137-byte response. It contains an RCS consumer row with
client enum 2 and consent enum 1 (`CONSENTED`), which the reference consumer-
specific check accepts. This establishes consent lookup, not number verification. The repository Rust
implementation independently repeated the successful consent lookup using the
actual cached token subsequently issued by Sync. Its decoder reports the RCS
state as consented without exposing identity/proof inputs.

The successful request used a fresh owned RSA-derived IID registered for project
`496232013492`, an owned EC public key, a genuine microG-backed DroidGuard result
for flow `constellation_verify` bound to `rpc=getConsent`, and actual checkin
Android ID in header `ClientInfo.DeviceId` fields 2 and 4. User serial field 3
was legitimately zero. The root DeviceId contained only the IID token, matching
`brdw.d`. The request carried no IMSI, IMEI or phone number.

Checkin Android ID is not `Settings.Secure.ANDROID_ID`: `brao.a -> bqpj.d ->
biry/birt -> CheckinApiService -> bisb/bise` resolves authenticated Google
checkin state. Filling that actual ID in the header resolved the prior field-
validation error. This does not resolve the separate read-only GPNV rejection.

No account OAuth or client signature was supplied. `GetConsent` intentionally
omits client authentication; first Sync advertises the owned EC public key and
requires acknowledgement before signed follow-up requests. The inspected
response contains no cached DroidGuard token, so Sync needs a fresh proof bound
to `rpc=sync`. Never reuse a raw proof under a different RPC binding.

Wire corrections checked against generated descriptors: legacy consent state is
inner field 2 and detail is field 3; RCS consumer rows use client field 1/state
field 2. The earlier private research template incorrectly labelled legacy state
field 1; that was corrected before implementing its Rust decoder.

## 6. Initial Sync selects a real TS43 challenge

**Observed live:** an independent first `PhoneDeviceVerification/Sync` returned
gRPC status 0 and a 4,842-byte gRPC frame. The verification is `PENDING` (wire
state 2), with method enum 11 (`TS43`) and operation `AcquireTemporaryToken`.
The response issued a cached DroidGuard token with an expiry. No verified-number
JWT or completed RCS provisioning document has been obtained.

The request used actual active-SIM association data, a fresh proof for
`constellation_verify` bound to `rpc=sync`, the existing owned EC public key,
RCS consent parameters and the reference caller's certificate/nonce format.
The nonce hashes UTF-8 `caller_session_id + "." + IMSI` using SHA-256. The
caller certificate is padded standard Base64 of the oldest signing certificate's
SHA-1 digest, which differs from the HTTP header's hex format. Optional
telephony capability fields and platform-number-source rows were omitted in this
bounded probe; it does not establish complete reference-client parity.

SIM identifiers were read privately through the default SMS application's
existing access. The installed microG process could not read IMSI through its
current permissions; no additional phone permission was granted. The request
contained the real selected SIM; it did not claim a fabricated number or proof.

The selected handler is `brxy -> brxd -> wej/weu/wew`: authenticate to the
provided carrier URL, use the actual SIM's `getIccAuthentication(2,129,...)`
result for EAP-AKA, then acquire the temporary token. `Proceed` must carry the
full carrier JSON response, the original verification and the exact opaque
challenge context, preserving unknown fields. The subsequent carrier exchange
is described below; a selected challenge alone does not establish verification.

No EC-key acknowledgement was present in the response header. The reference
client leaves the first follow-up unsigned until it receives that acknowledgement.
Actual unknown response-header fields 2/3 remain private and are not assigned
invented meanings or echoed as invented request fields.

## 7. GMS compliance and ACS attestation are separate

Static original-GMS evidence resolves service 257:

```text
Action: com.google.android.gms.gmscompliance.service.START
Binder: com.google.android.gms.gmscompliance.IGmsDeviceComplianceService
Backend authority: android.googleapis.com:443
RPC family: GmsCompliance/GetEnforcement
DroidGuard flow: dcs_get_verdict
```

This produces a device/GMS compliance verdict. The Binder response contains a
serialized backend result; it is not an RCS authentication credential. The
inspected implementation also has fail-open paths. Modern runtime logs show
microG receiving a `dcs_get_verdict` initialization request, which still does
not establish an ACS attestation result.

The separately inspected RCS content-binding path uses DroidGuard flow
`rcs_provisioning` (`ejth`/`ejti`). `ejtc.o` constructs its map from available
subscriber/verification values, session state, the ACS cookie, a salt and, for
newer binding versions, the challenge. `fzab -> fugq -> fuha` selects SHA-384:
`p(value, salt)` hashes UTF-8 `value + salt`, represented by the hash object's
string form. For version >=2, the map additionally binds the salt hash,
content-binding version, application name and available challenge/temporary
SIM token. Exact surrounding wire encoding remains under investigation; no
fabricated or transplanted attestation token was used.

**Observed live:** the existing Messages DroidGuard client, backed by microG,
completed flow `rcs_provisioning` with a version-2 content-binding map made from
the real challenge, cookie, genuine GMS-context push token and fresh session/salt.
It returned a nonempty encoded result, retained privately. This establishes
local token generation, not ACS validation, subscriber provisioning or RCS
registration. The normal app flow remains blocked earlier at number verification.

## 8. Real SIM authentication and carrier temporary token

**Observed live:** the selected carrier URL returned an EAP-AKA challenge.
The installed AOSP entitlement implementation, invoked in the privileged Phone
process, used the selected SIM's real authentication result and composed the
EAP response. The combined initial request, SIM operation and cookie-preserving
relay completed in about six seconds and returned a carrier authentication token.
SIM secret key material remained in the phone process.

The carrier then accepted `AcquireTemporaryToken` and returned the full JSON
response containing a temporary token. Its unverified JWT payload identifies the
selected subscriber and names Google as its audience. Decoding those claims is
not signature validation or proof that Google accepts the token.

The relay cookie expires after 30 seconds. A manual exchange initially failed
after that cookie expired; the timed combined exchange succeeded. TLS certificate
verification remained enabled. The working Linux curl connection negotiated
TLS 1.2 with `AES256-GCM-SHA384`, a static-RSA cipher unavailable in rustls.
A failed Python connection does not establish a TLS-version-only problem.
An Android platform transport is therefore relevant to this carrier integration.

**Observed live:** `Proceed` accepted the reconstructed RPC envelope with outer
gRPC status 0, but returned verification state `NONE` and reason `FAILED` (2).
It received the original verification, the unchanged opaque context, the full
carrier JSON and a valid cached DroidGuard token. The carrier token was still
within its declared validity window. The older challenge had been held during
inspection; challenge expiry remains a hypothesis, not an established cause.
No verified-number credential was returned.

Later fresh `Sync` attempts returned reason `THROTTLED` (1), with per-record
code 8 and a message explaining that too many recent verifications or attempts
had exhausted the resource. Outer gRPC success must not hide this record failure.
The status schema is original GMS `jcvk`: code field 1 and message field 3;
field 2 is unknown in the inspected descriptor. It is not `google.rpc.Status`,
and the message is not a protobuf `RetryInfo`.

The returned timestamp pair yields no positive retry duration under `brwb.b`'s
millisecond subtraction. Messages normally applies exponential retry delays
starting at 60 seconds and capped at 86,400 seconds; that client schedule does
not reveal the server quota reset time. Verification probes were stopped after
the later retry remained throttled. No IID or SIM identity was changed to evade
the limit.

Static `brxd` evidence also establishes that HTTP history is an optional
challenge-response field, enabled by default. Whether the backend needs it for
this particular token remains unverified; synthetic history is not evidence.

## 9. Direct TS43-to-ACS path

Current Messages also contains `ejts -> ejtx -> ejwd`, which obtains a carrier
temporary token and submits it directly to ACS. This is distinct from the
Constellation verified-number-token flow. The multipart fields are
`as_temp_token` and `client_authenticity_result_<method-id>`; the latter holds
Base64-encoded content-binding protobuf. Version 2 binds the temporary token
under `SIM_AUTH_TEMP_TOKEN` together with the actual challenge and session cookie.

**Observed live:** early requests with provisional metadata returned HTTP 400
with empty bodies. Static comparison found concrete mismatches in the session
header, client version, user agent, profile/version, initial-only query flag,
and SIM identifier/proof binding. These were corrected together; the next
request returned HTTP 200 and a 453-byte WAP provisioning document.

That document contains version **0**, validity **86,400 seconds** and
`XGOOGLE/InvalidConfigDetails/InvalidConfigReason` set to
`INVALID_CONFIG_REASON_UNSPECIFIED`. It contains no subscriber credentials.
This is an invalid configuration, not successful RCS provisioning, and does
not independently establish an attestation verdict. The existing carrier
authentication token was reused to acquire a fresh temporary token; no new
SIM authentication or Constellation request was needed.

The reference session header is `rcs_engine_session_id`; the DroidGuard map
key remains `PROVISIONING_SESSION_ID`. Profile and version are separate
`UP_T` and `5.1B` values. The multipart POST omits the initial GET
`client_authenticity_support` query flag. Actual IMSI and IMEI in the query
are bound by corresponding salted SHA-384 map entries; captures stay private.

## Next executable work

1. Preserve the verified Rust discovery, initial ACS and consent paths, and
   decode verification results without treating pending or outer RPC success as verified.
2. Trace handling of the invalid ACS configuration and reconcile remaining
   MLS/client-state requirements with current Messages.
3. Respect verification backoff, then diagnose `Proceed` using a fresh challenge
   and genuine carrier response without inspection delays.
4. Obtain authorized provisioning, then registration and the first two-way
   Google Messages RCS exchange. Those goals are still open.

## Evidence locations

Private root: `Downloads/pixel4a-geekbox/rcs-gapps-re/` under the user's home.
`messages-static/` contains source and DEX instruction references tied to the
current APK digest; `mobileconfig-static/` contains the reconstructed schema,
schema assertions and actual RPC artifacts; `runtime/` contains bounded device
traces and backups; `carrier-static/` contains Carrier Services and offline GMS
findings. Private credentials, request bodies and identifiers are not reproduced
in this report.
