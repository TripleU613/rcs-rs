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

For the initial minimal MCC/MNC request, which omitted the installed GMS package,
the actual response selected:

| Field | Observed value |
| --- | --- |
| ACS | `rcs-acs-tmo-us.jibe.google.com` |
| RCS enabled state | Enabled (raw enum 1) |
| Skip header enrichment | true |
| RCS profile/version | `UP_T` / `5.1B` |
| IMEI/IMSI format | Ignored (raw enum 4) |
| DroidGuard with HTTP GET | true |
| UPI enabled state | Disabled (raw enum 1); corrected against `gefi`/`ddml` |
| Direct TS43 provisioning supported | false (field 55); no ECS URL in field 56 |

Raw PII enum values must not be confused with the old client's internal format
integers. In the current artifact, `geef.c(4)` maps to enum representation 6,
`PII_FORMAT_IGNORED`. The later `ejuz` call chain nevertheless maps this
representation to sending full identifiers. The enum label alone establishes
neither omission nor a server requirement for full identifiers.

**Routing correction from a controlled comparison:** the original minimal
discovery request was insufficient to rule out other routes. Current Messages
`elml.a` sends both its own package/version and the installed GMS package/version.
One five-condition discovery RPC held GSF ID zero and the device/app metadata
constant. Adding GID1, the genuine first eight IMSI digits and Android carrier ID
did not change the route. Adding installed GMS version **252432034** to that
carrier context changed UPI to raw **3** and direct TS43 to **true**, supplying
the carrier ECS URL and entitlement version 12.0.

A second single RPC isolated only the package entry: minimal versus identical
minimal-plus-GMS requests returned the same difference. The exported Rust CLI,
after `Probe::with_gms_version` was added, independently obtained UPI raw 3 and
direct TS43 support. Thus the GMS entry causes the observed routing difference
in these requests; this is not evidence of subscriber admission. Private captures
are in `runtime/route-audit-20261016/` and `runtime/route-audit-gms-isolation/`.
GSF was held zero, not substituted with microG's checkin ID. The earlier
read-only lookup in the Phone caller context returned no ID; section 13 records
why that did not establish the actual Messages value. This comparison alone
was not complete native-request parity.

UPI's enum differs from the RCS-enabled enum. `gefi.a` maps raw 1 to internal 3,
which `ddml` names DISABLED; raw 3 maps to ENABLED_WITHOUT_ACS_FALLBACK. Earlier
text treating UPI raw 1 as enabled was incorrect. The direct-TS43 route remains
separate from UPI's inner TS43 verification method.

Response shape: field 1 repeats configurations; each configuration has its
correlation ID in field 1, validity duration in field 2 and onboarding flags in
oneof field 3. Onboarding ACS is oneof field 2 (direct hostname) or field 3
(MCC URL format). The server also returned fields absent from this client
schema; they must not be mislabelled or treated as a decode failure.
Response-root field 2 contains packed repeated **uint32** experiment IDs;
section 13 records their consumer and the correction from the earlier int32 type.

## 2. Google ACS issues an actual challenge

This probe explicitly requested `client_authenticity_support=goog-droidguard`.
Current `ejts` uses that challenge for direct TS43; it does not establish that
the normal legacy IMSI/MSISDN/OTP route always begins with this XML challenge.

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
`goog-mls-config-refresh` (`ejvn.k`). A later initial UPI challenge GET was
exercised live; credential-bearing UPI provisioning remains untested.

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

## 4. Constellation token acquisition

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

**Follow-up source audit and live read-only probe:** original `brad.c` gets a
project-specific token for the configured read-only project, default
`745476177629` (`jseq.e`). It shares the RSA-derived IID identity with the full
verification project, but the two tokens are not interchangeable. The retained
owned tokens were checked to have the same prefix, matching the owned RSA public
key; no registration or identity reset was needed for this follow-up.

Unlike Sync, this read API signs without checking the public-key acknowledgement
flag. `jsgf.h` defaults to true: `brad:81–94` signs UTF-8
`iid_token:timestamp.seconds:timestamp.nanos` with the persisted EC key using
SHA-256/ECDSA (`brdt.e`). Credentials contain IID field 1, DER signature field 2
and Timestamp field 3. The caller certificate/package/nonce are fields 1/2/3 of
`joxp`; selection 2 requests RCS records. The default `jsgf.l=true` omits
DroidGuard on this read API. Those are shipped defaults, not recovered effective
server configuration.

A correctly signed query at **14:36 UTC** used the existing owned read-only IID,
the same owned EC key as the full-flow probe, and the actual caller binding.
Local verification accepted its signature and rejected altered signing input;
independent source review checked its request. Google returned outer gRPC code 8
with structured `RATE_LIMIT_EXCEEDED`, quota
`GetVerifiedPerMinutePerProject`, metric `getverified_requests`, limit
**1,350,000 requests/minute/project**, location `global`, for consumer project
`745476177629`. It returned no records. This project-level read quota is a
different response from Sync's per-record verification-attempt exhaustion.
Neither proves that IID, signature or subscriber admission would pass later
checks. Private evidence: `constellation-static/gpnv-signed-attempt01/`.

A single signed recheck at **14:39 UTC**, more than 125 seconds later, returned
**gRPC status 0 with an empty record list**. It retained the same owned IID/key
and supplied a fresh signing timestamp and read-request session. No registration,
Sync or carrier call ran. This demonstrates an accepted read request; there is
still no verified-number record or credential. The first quota response was not
a zero-quota endpoint. Historical unsigned failures and this result also differ
in the established full-flow EC context, so they do not isolate signature
omission as the sole earlier cause. Private evidence:
`constellation-static/gpnv-signed-attempt02/`.

The Rust `verification::read_verified_numbers` implementation follows this
observed signed read path, sharing the existing bounded TLS/gRPC transport. The
host supplies its project-specific IID, owned EC signature and exact signing
time; `read_numbers_signing_input` provides the bytes to sign. Signature size is
bounded, but the library does not validate key ownership, signature freshness or
returned credentials. Response decoding retains the original record bytes
(including timestamp/unknown fields), bounds text/record counts, rejects duplicate
known singular fields and redacts private values. Empty results remain empty;
project quota errors are returned without automatic retry.

At **14:47 UTC**, a separate private Rust consumer of that exported API also
completed successfully with zero records and zero credentials. It signed fresh
library-provided bytes with the same owned EC key; no phone instrumentation or
new verification request was used. The original response is 38 bytes despite
the empty record list: unknown root fields are retained rather than counted as
records. Private evidence: `constellation-static/gpnv-rust-attempt01/`.

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
The temporary response wrapper is `joty`: its only string is **field 2**, as
established by its original generated descriptor. It is nested under `jotz`
field 3; the context is `jotz` field 1 and HTTP history is repeated string field 5.

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

**Observed live:** the earlier `Proceed` RPC returned outer gRPC status 0, but
verification state `NONE` and reason `FAILED` (2). A later independent review
found that this probe put the full carrier JSON in `joty` field **1**, whereas
the original descriptor requires **2**. It therefore does not establish that
Google received the carrier JSON as a known field. The original verification
and context were preserved, and the carrier token had not expired; the older
challenge had also been held during inspection. Incorrect payload tagging and
challenge age are distinct possible causes, neither isolated by that attempt.
The original capture is retained unchanged. No verified-number credential was returned.

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

The Rust library now builds initial `Sync` and unsigned TS43 `Proceed` requests,
reusing the existing consent header validation. Independent synthetic wire
fixtures and real localhost HTTP2/gRPC tests check exact payloads, metadata,
single-call behavior and failure preservation. Review corrected the `joty`
field tag and an example bug where an expired captured cache could replace a
fresh proof. Signed ClientAuth, carrier transport and SIM operations remain
outside these Rust request functions.

At **07:02:33 UTC on 2026-10-16**, after roughly 33 minutes without another
verification attempt, the Rust `Sync` call returned state 1, reason 1 and record
code 8 (`THROTTLED`). It issued no pending challenge. The timed driver stopped
before carrier authentication or `Proceed`; the corrected payload still lacks
a fresh live acceptance test. Temporary root debugging and the USB forward
were removed afterward, with USB ADB retained and stay-awake restored to 0.

A controlled same-subscriber/IID Rust retry at **08:08 UTC** followed more than
65 minutes without another verification RPC. It again returned NONE (1),
THROTTLED (1), record code 8, with no credential or pending challenge. The job
stopped before carrier authentication or Proceed and completed its temporary
debug cleanup. The captured response was decoded offline with the same result.
There is no accepted subscriber configuration or RCS service session. UPI
registration depends on the missing verified-number credential. The later
discovery correction in section 9 establishes a separate carrier-to-ACS route;
its admission failure must be investigated independently of the UPI quota.

After the user resumed work, a single same-identity Rust Sync at **14:30 UTC**,
more than six hours after the previous attempt, again returned NONE (1),
THROTTLED (1), record code 8. There was no public-key update, pending challenge
or number credential. Carrier authentication and Proceed did not run. The
360-byte response was independently decoded offline; the one-shot job is
terminal, its debug server and forward are removed, and no further Sync is
scheduled. Private evidence: `constellation-static/rust-attempt07/`.

The earlier failed challenge is not an established alternative. Original
`bqzr.e:651–719` continues only while the current returned record is PENDING;
`bqzr.d:605–615` preserves a pending record after a transport exception, but our
historical Proceed returned a terminal NONE/FAILED record successfully. No
server challenge TTL was recovered. The read-only API returns existing verified
records without pending challenge/context, so it cannot restore that challenge.
Replaying the historical pending snapshot would not reproduce normal client
continuation and would not isolate challenge age from terminal consumption.

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

**Further observed live:** the omitted participant proof was reconstructed using
fresh owned P-256 keys. Messages' native signer produced a DER ECDSA signature
that independently verified using Java and OpenSSL with the
[RFC 9420 SignWithLabel encoding](https://www.rfc-editor.org/rfc/rfc9420.html#section-5.1.2).
The application label is `ACS_Participant_Key_Proof`, and the content is the raw
UTF-8 ACS nonce. Public key SPKI DER and signature are unpadded Base64URL in
`participant_public_key` and `participant_key_signed_nonce`. The running app's
`home_kds` routing value was read as 2. No existing application identity keys
were read or replaced.

A fresh ACS exchange including those fields returned the identical version-0
invalid configuration. Adding the participant proof did not resolve the remaining failure in this
tested request. The response contains no explicit
attestation verdict.

The earlier conclusion that discovery disabled this route was based on an
incomplete request. Section 1 records the controlled comparison: adding the
actual installed GMS package/version enables direct TS43 and supplies its
entitlement endpoint. A separate type-3 policy lookup returns
`upi-carrier-tos-ts43` for that profile; the minimal profile instead receives
`upi-mo-strict-policy-mt-priority`. UPI and legacy builders copy this policy to
`supported_provisioning_types`; the direct TS43 builders omit that header.

**Direct test with corrected discovery:** attempt05 used the newly advertised endpoint, realm
`nai.epc`, entitlement version `12.0`, fresh real EAP-AKA and an `ap2014`
AcquireTemporaryToken operation. Its ACS exchange included the selected policy,
genuine challenge-bound version-2 platform proof and a fresh owned participant
key/signature. ACS again returned HTTP 200, 453 bytes, version 0, validity 86400,
unspecified invalid-config reason and no APPLICATION credentials. This does not
identify which admission check failed. It establishes that the UPI verification
quota is not the only route worth investigating.

Original Messages `ejvj.h` selects direct TS43 before UPI only when discovery
enables it and local GMS availability at version 254500000 succeeds. The
installed compatible implementation is below that local threshold. The host
probe uses the independently working AOSP SIM adapter; it does not claim that
normal Messages passed this SDK check. The genuine DroidGuard platform helper
also remains a laboratory dependency, not proof that an arbitrary SMS app is
admitted.

Private evidence: `runtime/route-audit-{20261016,gms-isolation,policy}/` and
`constellation-static/acs-ts43-attempt05/`. Earlier negative direct tests alone
cannot rule out this newly confirmed route.

**Cellular comparison:** the same source-backed direct flow was then executed
through Android's validated cellular INTERNET network for the selected SIM,
using `Network.openConnection` with normal HTTPS certificate verification.
It reused the still-valid carrier token and generated a fresh ACS challenge,
session, genuine proof and owned participant key. The POST again returned HTTP
200, 453 bytes, version 0, validity 86400 and the same unspecified invalid reason,
with zero APPLICATION entries. Thus this network-path change did not resolve
the tested direct request. Fresh challenges/proofs and the phone HTTP stack
also changed, so this is not a byte-identical IP-only experiment. No UPI
verification RPC or identity reset was performed. Private evidence:
`constellation-static/acs-ts43-cellular-attempt01/`.

**Subsequent header correction:** a whole-APK reference search found that
`ejuz.d` is the sole policy-header setter, called by eight UPI/legacy request
builders but neither `ejts.j` nor `ejwd.j`. The direct common HTTP and MLS
builders do not inject it later. Attempts05 and cellular01 therefore carried
an extra header. Attempt06 removed it from both GET and POST, with fresh real
carrier authentication, temporary token, challenge and platform-generated
version-2 proof. It again returned HTTP 200, 453 bytes, version 0, validity
86400, unspecified invalid reason and zero APPLICATION entries. The fix improves
request parity; it did not resolve the tested rejection. No UPI number RPC was
made. Private capture: `constellation-static/acs-ts43-attempt06/`.

## 10. Legacy IMSI activation comparison

The separately returned minimal profile has UPI disabled, direct TS43 disabled,
skip-header-enrichment true and proactive DroidGuard GET enabled. `ejvj.h`
therefore selects the normal legacy IMSI route for that profile. The policy
name `upi-mo-strict-policy-mt-priority` is still sent verbatim; no client-side
policy-name veto was found. This profile is not equivalent to the installed-GMS
profile, whose raw-3 UPI mode has no legacy fallback.

`ejvs.c -> ejuz.h -> ekcb.e/f` sends an ACS-base GET with actual formatted IMSI,
IMEI and GID1, metadata, empty `token` and configured `SMS_port`. There is no
`client_authenticity_support`, carrier token, multipart body or `/provision`.
The proactive proof is sent in `Droid-Guard` and `Droid-Guard-Salt` headers.
Its version-1 map has plain `APP_NAME`, salted SHA-384 IMSI and logical session;
the legacy builder does not assign IMEI to this map despite its query presence.
Cookie and GMS-IID bindings are added only when populated. Initial empty Cookie
and show-Google-TOS false require neither binding. No preliminary nonce fetch is
required by this source path.

**Observed:** selected-SIM cellular requests timed out with no captured HTTP
response at local read limits of 15 and 45 seconds. These were shorter than the
recovered reference timeout of 60 seconds (`ekah`, applied by `ejvb.a`); they do
not establish rejection or that the server did not process the requests. A
controlled host request reused the same logical session, salt and genuine
platform result, used the reference 60-second read limit and returned HTTP 200
with a 453-byte WAP document: version 0, validity 86400, unspecified invalid
reason, zero APPLICATION entries. No OTP challenge was recovered. No UPI
verification RPC or SMS send was performed by these probe scripts.

Thus the tested legacy request also failed to obtain subscriber configuration.
Neither this result nor the direct-route response identifies whether client
metadata, proof admission, subscription eligibility or another server check
caused the invalid configuration. Private evidence:
`constellation-static/acs-legacy-cellular-attempt01/`.

## 11. Native encoder and proof diagnostics

An offline runtime comparison used the installed current Messages classes with
retained owned test inputs. It made no activation request:

- `ejtc.o()` produced the same nine version-2 binding entries and hashes as the
  host implementation. `ejtc.n()` encoded byte-identical `fzaa` proof bytes.
- `ekrn.c`, `ekow.a`, channel and locale matched the host's client version,
  User-Agent, channel and language.
- Native `ekcb` query assembly matched every decoded host query parameter using
  the same supplied profile, actual owned identifiers and an empty configuration
  version/state. No `ejuz` instance was found in the heap, so this check does
  **not** establish live configuration-provider parity or successful routing.

The independent source audit found that the probe's `efxm.c().a()` defaults
match the reference's null-extra initialization. The option boolean means
`reinitializeHandleOnGetSnapshot`; it is not an express/manual selector.
The one-shot helper and reference cached handle call the same snapshot API.
`efxp.a` only encodes the result; it does not validate an attestation verdict.

The actual installed microG APK (version 252432034, SHA-256
`e5e6cba078bdec812b5450599350e5c1a12c8b7438da5bf77123af170f8c1a35`)
has a generic signed-VM handle/snapshot path for RCS. Its known local error
fallback is short ASCII beginning `ERROR : `. Unwrapping retained Messages
results from direct05, cellular01, legacy01 and direct06 yielded binary VM
snapshots of 23,958–25,863 bytes, none with that error prefix. This rules out
that known fallback in those captures, not negative server attestation. The
actual microG embedded/remote runtime preference was not inspected.

Messages `efxe` wraps VM bytes in `fsgj` field 2 with random prefix field 1,
timing telemetry field 3 and client UUID field 5. `fsgh` telemetry is repeated
event/elapsed-time pairs; successful local snapshot events are not a Google
verdict. Source evidence: REA `ev_91341043a64426388fa47e83dedbecfb60e350018630f35f86f980113e5ba262`
and `ev_04df788fa490c10c348930fa3bfd6886b352d79dffe9c89d6dda00c82113db6e`.

The invalid-config parser (`ekae`) reads the server's literal reason. Its enum
has a distinct `ATTESTATION_FAILURE` value, but these responses explicitly say
`UNSPECIFIED`. Client source cannot establish whether the backend discloses every
attestation failure that way. There is no supported basis to label the present
failure as definitively attestation, carrier eligibility or a number quota.

The MLS participant proof also supports first-use local P-256 key generation.
`dmoe -> dbyq -> daai` generates keys when absent, persists them in the local
settings database and signs the nonce; `dmnx` adds the public key/signature/home
hint. No prerequisite KDS registration or certificate RPC was found in that
construction path. Server rules for replacing a previously enrolled key remain
unknown; no existing application private key was read or replaced.

Private runtime evidence: `constellation-static/native-parity-20261016/`.

## 12. Explicit owned-number diagnostic

`ejvu.c` implements legacy RequestWithMsisdnState. Its query adds `msisdn`, and
its `msisdn_source` header uses literal values such as `msisdn_source_sim`.
The default version-1 proof binds the same selected MSISDN string, IMSI, session,
and any populated cookie/GMS IID. It leaves IMEI unassigned in the proof despite
its query presence. This differs from both UPI and the initial IMSI-only stage.
The SIM-number preparation path normalizes when possible and can retain the
original on failure; strict E164 is not guaranteed by that source alone.

This state is supported, but it is **not** an automatic fallback after the
captured HTTP-200 version-0 document. The initial IMSI handler sends a parsable
document to configuration processing; its MSISDN transitions instead include
a pending explicit-number request or HTTP 403 with the sharing gate satisfied.
No after-one-IMSI-attempt transition was established. The minimal profile allows
reading the SIM number (`inhibit_reading_msisdn_from_sim=false`), and its two
ignored PII formats permit sharing without the seamless-provisioning flag.

**Observed separate experiment:** a single host GET used the actual SIM number
(already international, matching the carrier token's own line), matching query
and proof inputs, `msisdn_source_sim`, empty initial Cookie and a fresh
platform-generated proof. No carrier token or Google number credential was sent
on this legacy path. ACS returned HTTP 200 and the same 453-byte version-0
configuration with unspecified invalid reason and zero APPLICATION entries.
No OTP challenge or accepted subscriber credentials were recovered. The scripts
made no UPI verification RPC or explicit SMS-send call. Private evidence:
`constellation-static/acs-legacy-msisdn-attempt01/`.

## 13. GServices ID depends on the caller context

Discovery's field-2 ID comes from the GServices provider, not Android's scoped
Settings.Secure ID. Current Messages `ellt.b -> auqu.ho -> auqt` case 427 calls
`eiop.b(contentResolver, "android_id", 0L)`. `eioq/eioz` queries
`content://com.google.android.gsf.gservices` and parses column 1 as a signed
decimal Java long. Missing/null/nonnumeric values fall back to zero; this helper
does not swallow a SecurityException.

The installed microG provider restricts `android_id` to its own UID, recognized
Google packages and device/profile owners. READ_GSERVICES alone does not grant
that value. Thus our earlier empty Phone-process lookup was not equivalent to
the Messages caller. A later read-only invocation of the actual getter inside
Messages returned a nonzero value, retained privately without changing identity.

No check-in-ID substitution was made: microG stores CheckinResponse.androidId
in LastCheckinInfo but fills GServices rows separately from response.setting
entries. Source alone did not prove those IDs were equal.

Two controlled discovery requests used the actual Messages value versus zero,
holding device/carrier/package inputs constant. Both succeeded: individual
configuration messages were byte-identical after excluding cache validity,
including unknown onboarding fields and policy bytes. The response-root
experiment IDs **also differed**, so the whole responses did not differ only
in validity. No verification or ACS request was made by this comparison.

Generated `gedv` uses descriptor type 43, `UINT32_LIST_PACKED`, for response
field 2. Whole-APK field references find only two consumers, both in
`ellm.apply`. Changed IDs go through `ehrb.t -> ehqv` to Phenotype weakRegister
with namespace `__internal.external_ids#MOBILE_CONFIGURATION_NAME_SPACE` and
the Android Messaging or Carrier Services log source. No direct ACS header,
query or route-state consumer was found. Indirect experiment-service effects
are not excluded. Rust's wire type is corrected to packed uint32; a synthetic
maximum-value round-trip test exposed the old signed type's ten-byte reencoding.

This closes a client-context gap without explaining the present admission
failure. `Probe::with_gsf_android_id` now permits that actual signed value;
callers that omit it retain zero and the original request bytes.
Private evidence: `runtime/gsf-messages-audit-20261016/`,
`runtime/route-audit-native-gsf/` and `runtime/route-audit-gsf-zero-control/`.

## 14. Native activation state and local SDK gates

Read-only checks in the actual Messages process and its settings UI on
2026-10-16 establish:

- Messages is the default SMS app, RCS is enabled, and the UI says “Connecting…”.
  `ekqw.h(context)` is true and `ekqw.a(context)` is 2: the app selects external
  Carrier Services. Service-process existence alone did not establish this.
- Provisioning runs in the main process's transient
  `RcsProvisioningListenableWorker`, through `dmls -> ejuq.a -> ejuw`.
  Missing `ejuw` instances in idle main or `:rcs` processes are expected.
- The actual SIM's state cache reports `RetryState`, retry count 11, last
  attempt `2026-10-16T14:29:35Z`, and next attempt
  `2026-10-17T07:33:36Z` (03:33 EDT). A consistent WorkManager snapshot separately
  confirms the completed worker and queued delayed replacement. No retry was
  forced and no verification RPC was sent during these checks.
- The cached configuration is present but version 0, validity 0, state 0 and
  unspecified invalid reason, with no ACS token or MLS configuration.
  `has_provisioned_once=true` is not success: `ejuw.v()` sets it whenever any
  configuration exists, including an invalid version-0 cache.

The native `ddmr` flags match corrected Rust discovery: direct TS43 true, UPI
wire 3, skip HE true, DG-with-GET true, IID inclusion false, profile UP_T/5.1B,
PII rules wire 4 and policy `upi-carrier-tos-ts43`. Actual Messages-context IMSI,
IMEI and GID1 getters match the owned inputs used in the earlier independent
ACS tests. A separately constructed native `ejuz.a()` builder, using the live
configuration and subscription providers, also returns matching profile,
version, vendor, form factor and identifier fields. Its constructor and metadata
getter do not start activation. This closes the earlier supplied-input-only
comparison; it does not establish complete native HTTP or successful attestation
parity.

The native availability check for direct TS43's minimum GMS version 254500000
returns 2 (update required). A cached GMSCore IID exists, but no cached ACS token
does. With these inputs, `ejvj.h()` would choose UPI `gizz.F` if ReadyState runs.
UPI GC is enabled, so its zero attempt counter does not prove that verification
was never entered: this branch deliberately skips that counter. The separate
UPI availability threshold is 204390000; the actual native check for that
threshold returns 0 (success).

The installed microG artifact has two concrete SDK coverage gaps. Its manifest
routes Constellation service155's action to `org.microg.gms.DummyService`, which
unconditionally returns `onPostInitComplete(23, null, null)` (`API_DISABLED`).
It has no direct service-entitlement service359 implementation or advertised
`service_entitlement_1p_api` feature. Current Messages uses transaction7 of that
interface for direct carrier authentication. These are implementation gaps,
not demonstrated settings errors. In the UPI failure handler, API_DISABLED
takes `k(false)`; with GC enabled that enters Retry without legacy fallback.
This source path does not prove the exact error of the historical attempt.
Unrelated main-process API errors were not attributed to RCS.

A bounded live bind from the actual Messages process independently reproduced
service155 admission failure: resolved component
`com.google.android.gms/org.microg.gms.DummyService`, callback status 23, null
service binder. The probe checked that exact component before binding, sent
only the broker's GetServiceRequest for service155, and unbound afterward. It
did not reconnect a shared client, send a Constellation capability/IID/number
transaction, or initiate a backend verification request. This confirms the
current local SDK failure, while leaving the earlier attempt's precise history
unproven. Private result: `constellation-bind-summary.json` in the native
evidence directory.

Private evidence: `runtime/native-engine-20261016/` and
`runtime/baseline-local-20261016/`. Tokens and subscriber identifiers stay private.

## Next executable work

1. Preserve the verified Rust discovery, initial ACS and consent paths, and
   decode verification results without treating pending or outer RPC success as verified.
2. Keep direct ACS TS43 routing separate from TS43 inside UPI verification.
   The [provider-access record](provider-access.md) now traces the actual UPI
   `id_token` parameter through `/provision`, version-1 attestation binding and
   the two distinct session IDs. Rust exposes that optional private parameter
   without validating its claims or treating presence as verification.
3. Diagnose the advertised direct carrier route and the source-backed legacy
   ACS path using request/proof parity and subscriber eligibility evidence.
   The native encoder comparison and explicit-number diagnostic are recorded
   above; none established acceptance. A positive control for this exact line
   would help distinguish environment/subscription state from remaining protocol
   differences. Current captures do not identify the rejecting server check.
   The native baseline above now separates missing local microG SDK services
   from the independent direct request's unresolved server admission failure.
   The cellular direct-route comparison did not resolve the invalid config;
   legacy cellular timeouts remain inconclusive. Keep UPI's verification throttle
   separate; the research probes have no automatic retry loop or scheduled
   verification request. Messages retains its own queued provisioning worker.
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
