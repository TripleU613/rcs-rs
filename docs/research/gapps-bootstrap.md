# GApps RCS bootstrap: recovered behavior

Investigation dates: 2026-10-16 through 2026-10-19. Status: bootstrap discovery,
ACS challenge, consent lookup, a verification challenge, carrier SIM authentication,
independent check-in and direct own-context DroidGuard VM execution have been reproduced;
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
SIM token. Section19 records the recovered direct version-two wire encoding;
no fabricated or transplanted attestation token was used.

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

## 15. Native request and owned-key signing controls

The following laboratory controls narrow the client-side differences. They do
not establish accepted provisioning, a working RCS session, or admission for an
ordinary APK without Google services.

| Control | Observed result | Limit |
| --- | --- | --- |
| Native request providers from the existing Messages application graph, with the actual selected SIM and cached ACS origin | Native GET returned HTTP200 and a 315-byte client-authenticity challenge on 2026-10-16 | A challenge is not an accepted configuration. The isolated observer did not apply the response. |
| Fresh carrier EAP exchange on 2026-10-16 using the owned SIM through the installed entitlement library in the existing Phone process | Challenge GET, SIM-response relay and temporary-token operation each returned HTTP200; a nonempty temporary token was returned | This used a privileged laboratory adapter. Its decoded future expiry claim was diagnostic, not JWT signature validation. The historical token must not be reused after expiry. |
| Subsequent paired-request preparation on 2026-10-16 | A fresh native GET returned HTTP200; the native parser, cookie handling and version-2 binding produced the expected nine map entries | The signing harness then failed before DroidGuard or POST. The complete paired request was not exercised. |
| Synthetic signing-only control on 2026-10-19 | A new volatile P256 key signed the synthetic nonce through the native signer; phone JCA verification and independent host verification passed, and changed content was rejected | This exercised an owned test key, not Messages' persisted participant identity or server enrollment. The harness invoked zero HTTP requests. |
| Complete native-helper request on 2026-10-19, after a fresh carrier exchange | Native GET returned HTTP200; genuine native DroidGuard computation, verified owned-key signing and native multipart construction completed; POST returned HTTP200 with a 453-byte version-0 document and no applications | The response was unusable. This closes the native HTTP/proof-encoder execution gap; normal MLS-provider enrollment and the reason for the unusable response remain unresolved. |
| Normal MLS-provider control on 2026-10-19, after strict local row inspection | The normal provider returned a participant-key proof over synthetic input; independent P256 SPKI/signature verification passed and changed content was rejected. A subsequent strict read found one valid row with both participant and device keypairs populated | First use persisted app keys through the normal provider. Only public proof material left the VM. The harness invoked zero HTTP requests; no server enrollment or accepted provisioning was demonstrated. |

The native HTTP control used a separate connection factory and transport with
real dependencies, a validated Internet `Network`, normal TLS trust, and an
isolated observer whose configuration-processing branch was disabled. Its
connection hook checked the owned HTTPS authority and disabled redirects before
the explicit network operation. Response bodies were bounded and captured
privately, with streams closed and connections disconnected. Later cookie
capture preserved each actual header-list element for native parsing.

The existing Messages `:rcs` process crashed during one preparation attempt,
with stack frames in the request-builder provider; it restarted. Another reported a transport
error without an HTTP status. A later GET succeeded. These observations do not
identify the ART crash or transport failure's root cause, and are not evidence
of server admission rejection. The installed Messages base hash was rechecked
against the analyzed artifact after the crash and again on 2026-10-19.

The signing harness required reflected access to the native signer interface
and an explicit `java.security.Key` cast for its inherited `getEncoded` method.
The final output was canonical, unpadded Base64URL containing a P256 SPKI public
key and DER ECDSA signature. The signing input used the actual native
`ACS_Participant_Key_Proof` label with a synthetic nonce long enough to exercise
the two-byte MLS length prefix. No persisted app identity was exported, created
or replaced by this control.

The complete request used the same fresh challenge, session, cookie, carrier
temporary token and native version-2 binding instance through proof computation
and transmission. Its identifier and cookie metadata matched that binding, and
the current native home-KDS flag supplied the routing hint. Multipart assembly
also needed a `dmox` view of the native builder because its concrete `dmol.b`
field hid the inherited `b(String,String)` method from the Frida wrapper. A
synthetic two-part construction passed before the complete attempt.

The returned document reports validity86400 and
`INVALID_CONFIG_REASON_UNSPECIFIED`, matching the earlier invalid-response
pattern. It gives no specific attestation, subscriber or enrollment verdict.
Producing a genuine DroidGuard snapshot does not show that the server accepted
its contents. The harness applied no response and scheduled no retry after this
unusable configuration. The retained owned-key-versus-normal-MLS-provider difference
prevents claiming complete activation parity.

Follow-up local inspection found no matching loaded store in `:rcs`. An ordinary
settings read there failed with a null-pointer exception; source inspection
also found that the database requires the normally initialized primary process.
The existing main process was Android-frozen. After bringing Messages to the
foreground through its normal launcher, the same metadata read succeeded and
returned no `1_2` participant/device-key entry. This describes the returned
settings view; an empty/default result does not prove that no identity exists
elsewhere or that a persisted row parsed successfully. The helper invoked no
signer, key-generation, settings-update or HTTP API. Opening the app can allow
its own background work, which this probe did not account for. No process guard
or retry-state override was applied. These results do not identify the server's rejecting
check or establish a need to replace keys.

The follow-up strict read queried the existing primary-process store directly
and invoked the native protobuf parser without its default-value fallback. It
found zero rows for this store. Calling the genuine normal MLS proof provider
then returned a nonempty public-key/signature result. Independent host
verification used P256/SHA256 and the MLS label framing; changing the content
invalidated the signature. The returned home-KDS hint matched the earlier
control. A second strict query found one successfully parsed row, containing
the selected `1_2` entry with nonempty participant public/private and device
public/private fields. Those flags do not independently verify the device
keypair or demonstrate server enrollment. No stored private key bytes were
exported. Normal first-use key creation and persistence were intrinsic to the
provider call; this was not a read-only control.

The full server request above still used a volatile key. A candidate using
the normal provider now preserves the actual ACS session and nonce through
signing and native POST construction, with host signature verification of the
captured proof. Offline tests cover session propagation, empty-proof and
routing-hint failures, and signature/framing rejection. This candidate has not
made a live request. The controller checks the native retry cache, and the
candidate rechecks the on-disk deadline immediately before each HTTP operation;
a missing, invalid or future deadline stops the attempt. The host also checks
the prior invalid reply's separate freshness policy, described in section 16.

A separate read on 2026-10-19 found native `RetryState`, retry count14, last
attempt `2026-10-18T22:06:35Z` and next attempt `2026-10-19T22:06:35Z`.
The legacy retry field was zero; it did not cancel the modern deadline.
Messages' RCS toggle was enabled and its visible status was Connecting.
These are dated local observations, not a fresh server verdict or permission
to ignore a subsequently rescheduled deadline. The three strict-read/proof
controls each invoked zero harness HTTP requests. The normally opened app
could perform its own background work outside those counters.

Owned debugging processes, forwards and output files were removed after the
captured controls. Where recorded, one RCS storage file's hash was unchanged at
return and its recovery backup was absent; this does not prove that every app
preference, telemetry store or background task was unchanged. The harness did
not call activation callbacks, configuration application, UPI verification,
SIP registration or messaging. The completed native multipart POST did not
yield subscriber credentials or establish a usable RCS session.

Private evidence under `runtime/platform-auth-audit-20261016/`:
`native-direct-get-summary.json`, `native-direct-carrier-20261016/summary.json`,
the `native-direct-coupled-20261016*` control summaries, and
`native-owned-mls-selfcheck-20261019-02/summary.json` with its independent
`host-verification-summary.json`. The completed attempt is in
`native-direct-coupled-20261019-02/`, with the fresh carrier result in
`native-direct-carrier-20261019/`. Actual challenges, cookies, identifiers,
tokens and request bodies remain outside Git.
The identity checks are retained in
`native-mls-identity-cache-20261019/`,
`native-mls-identity-cache-main-20261019/` and the
`native-mls-stored-identity-metadata-20261019*` summaries. The completed primary
process read is in `native-mls-stored-identity-metadata-main-20261019/`.
Strict row results are in `native-mls-strict-row-metadata-main-20261019/` and
`native-mls-strict-row-metadata-main-20261019-after-normal/`. The normal proof and
independent verification are in `native-normal-mls-selfcheck-main-20261019/`.
The dated retry state is in `normal-provisioning-cache-20261019/summary.json`.

## 16. Ordinary caller and invalid-response freshness

The installed compatible GMS APK was recovered again on 2026-10-19 and matched
the digest in section 11. Its version is `0.3.17.252432`, code `252432034`, below
the Messages direct-TS43 local requirement `254500000`. In this APK, Constellation's
service action resolves to a dummy service; the inspected inventory did not
establish a service-entitlement implementation. DroidGuard has an exported
implementation in the unstable process. These local service differences do not
identify the cause of the separate completed ACS request's invalid response.

An independently signed ordinary diagnostic APK loaded the installed
DroidGuard client classes and passed their public ABI check. One explicit call
then used the one-argument Context constructor, its actual own package in
APP_NAME, a synthetic input and the normal `getResults` API. It completed with a
32,019-byte encoded opaque result without the source-known local-error prefix. Only fixed
metadata was exported; the test host was stopped afterward. No carrier, ACS,
number-verification or MLS API was invoked by this probe. SDK internals could
perform their own network work. This establishes ordinary-caller SDK execution,
not an accepted attestation, usable subscriber configuration or operation
without microG. No Google caller package or signing identity was supplied.
Snapshot execution still goes through Binder to microG's service; this does
not establish VM execution under the diagnostic app's own Context.

A separate root-assisted metadata read found all ten inspected String fields
in the already active microG Build profile equal to `android.os.Build` in that
process: MODEL, MANUFACTURER, BRAND, DEVICE, PRODUCT, FINGERPRINT, ID, TYPE, TAGS
and HARDWARE. The read did not initialize, apply or replace a profile. It does
not establish every profile field, account state, hardware attestation, or a
server verdict.

The prior version-zero reply also has a timing effect that the older native
retry timestamp alone cannot represent. `ejug.a` retains validity `86400` and
records a new last-update time when applying this response. Configuration
`ad()` uses `validity - max(validity/10, 25200)` for that validity, without a
positive-version condition; `ejtj.i()` prevents ordinary provisioning
progression while the configuration remains fresh. The resulting threshold is
61,200 seconds, or 17 hours. Full validity is 24 hours; that is not evidence of a
server-enforced 24-hour throttle or an automatically scheduled retry.

Our harness did not apply its response to Messages. Its saved capture-write
upper bound was `2026-10-19T15:52:52.785434Z`, later than the request start.
Rounding upward gives a response-based earliest manual attempt of
`2026-10-20T08:52:53Z`, subject to any later applicable native or HTTP gate.
The saved GET and POST contain no Retry-After header. The native worker's
previously recorded October 19 deadline remains a separate observation.

The host now validates the retained JSON/base64/XML response and receipt bound
before permitting the full candidate. Reviewed capture digests and the exact
receipt timestamp are pinned; a new or changed capture requires review,
including a GET-only response. It stops on the fresh response, malformed
evidence or a Retry-After header needing review. Synthetic checks and an offline
check against the retained response confirmed that an early attempt stops
without device or HTTP calls. No new
manual ACS request was made for these checks; the full normal-key candidate
remains unexecuted.

Private evidence: `installed-gms-metadata-20261019/summary.json`,
`static/gms_discovery_review/installed-microg-252432034/`,
`ordinary-droidguard-probe/runs/`, `dg-profile-metadata-*`, and
`prior-invalid-reply-policy-verification-20261019.json` under the runtime audit
directory. The source trace is in
`static/gms_discovery_review/invalid-config-retry-policy.md`.

## 17. Independent ordinary-app check-in identity

Original source at microG commit
`ec206605ab97ada8369dade98ce822880f716033` closes part of the standalone-host
dependency question. The focused source, module builds and Apache-2.0 license
were retained and checked against the pinned Git tree's blob digests.
`HandleProxy` uses Android/Kotlin and a small exception wrapper; the whole core
module additionally imports profile, settings, broker and service dependencies.
Its VM callback `GuardCallback.b()` reads CheckIn.ANDROID_ID and returns decimal
Java-long text. Its random fallback is not an independently issued identity.
This is separate from Android's app-scoped ID and the GServices field in section13.

The original check-in client has a first-registration branch with androidId0,
no security token, fragment0, version3 and one empty account cookie. Its HTTPS
transport supplies no API key, OAuth token or Android caller-certificate header.
The original builder also has profile, hardcoded device/default and diagnostic
logging behavior that a truthful independent host must not inherit blindly.

The new [ordinary check-in probe](../../tools/android-checkin-probe/README.md)
implements that account-free branch with an independently signed APK, INTERNET
permission only, actual accessible `android.os.Build` fields and its own
User-Agent. It uses no GMS/microG, Messages, root, phone/SIM, account or shared-UID
API. Before opening HTTPS it durably records its own attempt; a separate host
intent prevents re-registration even after package loss. It accepts credentials
only when both returned fixed64 values are nonzero and durable private storage
has been reread. Neither credentials nor raw response data are exported.

On 2026-10-19, exactly one explicit registration completed with HTTP200 and a
374-byte decoded response. Both issued credential fields were saved. A separate
inspection after stopping the app returned credentials-present without a network
attempt, confirming persistence across that process boundary. The controller
checked the owned device, installed APK digest, user0, complete instrumentation
result and termination of only its own host. It did not call carrier, ACS,
number verification, DroidGuard or messaging APIs. The other installed apps'
background traffic is outside these probe counters.

The source now skips repeated supported unknown response fields while keeping
known singular fields duplicate-strict; that compatibility hardening passed
offline wire tests after the runtime baseline. The retained signed APK was
preserved with its original identity metadata. Current published source also
has compile/DEX and malformed-wire checks; no captured credentials are fixtures.

This establishes an independently issued check-in identity through ordinary
Android APIs, not accepted RCS provisioning or an accepted DroidGuard proof.
The phone still had microG installed; a physical no-GApps/no-microG portability
test remains open. Section18 records the subsequent own-context VM execution.
The normal-key ACS candidate and its response-derived wait in section16 remain
unchanged.

Private evidence: `static/upstream-droidguard-ec206605/source-manifest.json`,
`static/rcs_runtime/standalone-droidguard-boundary.md`,
`static/carrier-static/standalone-checkin-identity.md` and
`standalone-checkin-probe/runs/` under the runtime audit directory. The host
intent and Android app-private credentials remain outside Git.

## 18. Direct own-context VM execution

The independent test APK was updated with the same package and signing key.
Separate inspections before and after the update confirmed that its own issued
check-in credentials remained present. The host invokes the VM directly through
its own Android Context and ordinary UID, rather than delegating the snapshot
to microG's Binder service as in section16. The private diagnostic host source
digest is `6d3855617e532ead80ae1e8b9cf0c97d5b20b94150bc8346e989c32a56804af5`.

The bootstrap transport, wire schema, public verification anchors and callback
ABI were compared with the pinned source from section17. Its published SDK
default endpoint configuration was used with the test app's actual package,
Context, accessible Build fields and identifying User-Agent. Protocol version
constants describe interface compatibility. The callback returns the app's
own issued check-in ID; no ID or security token is exported from private app
storage. Unsupported callback operations stop the diagnostic.

Before any bootstrap request, a network-free on-device control verified the
host APK with Android SDK35's `apksig` implementation, matched its signer to
PackageManager and confirmed that the vendor certificate pin rejects it.
For downloaded code, the host verifies the exact signed response bytes before
decoding, requires an inline VM APK and bytecode, then verifies the APK's
signature and expected vendor certificate. It binds the read-only file by a
local hash before loading, checks class-loader provenance before initialization
and closes the constructed handle. The upstream permissive APK-verification
stub is not used. These checks do not establish future Android platform policy
compatibility beyond this tested environment.

On 2026-10-19, one explicit bootstrap returned HTTP200 and a 449168-byte decoded
response without Retry-After. The response signature and VM APK verification
passed; VM initialization, `ss(Map)` and close completed in the ordinary app.
The snapshot was 28365 opaque bytes, without the known local error prefix or
an unsupported callback. A fresh inspection reported the recorded attempt,
preserved own identity and no network attempt. Independent host and app journals
prevent automatic bootstrap repeats. No carrier, ACS, number-verification or
check-in registration call was made by this diagnostic.

This proves direct VM execution in the host's own Context. The snapshot was not
submitted to an RCS verifier and is not an accepted attestation. The phone still
had microG installed; a physical no-GApps/no-microG test remains open. Subscriber
provisioning, registration and two-way Google Messages RCS remain unproved.

Private evidence: `standalone-checkin-probe/vm-lifecycle-summary-20261019.json`,
`standalone-checkin-probe/vm-runs/` and the pinned source manifest from section17.
The vendor VM, bootstrap configuration, own signing key and app-private state
remain outside Git.

Subsequent inspection of that exact VM APK found a root-level ARM64 native
library, despite having no conventional `lib/<ABI>/` entries. Its five-argument
constructor selects the vendor's `GMS_CORE` runtime mode; distinct in-app paths
also exist. Thus the own Context result must not be described as a demonstrated
standalone vendor runtime mode or as physical no-GMS compatibility. The native
interpreter and its downloaded bytecode remain dependency boundaries.

## 19. Rust direct version-two proof binding

`acs::DirectBindingV2` now builds the direct-TS43 binding independently. It takes
the actual own app package, own logical session UUID, configured request
identifiers, exact GET cookie value and challenge, and genuine carrier temporary
token. A fresh UUID salt stays in the same binding instance for map construction
and proof encoding. Unavailable identifiers are omitted; required direct-route
context is rejected when empty or malformed. This does not grant ordinary apps
access to privileged SIM identifiers or carrier authentication.

The static reference is `ejtc.o/p/n` and `fzaa` from the Messages artifact above.
`fzab -> fugq -> fuha` selects SHA-384, and the inherited `fugl.toString()` formats
48 digest bytes as 96 lowercase hex characters. The map hashes UTF-8 value+salt;
DROIDGUARD_SALT hashes only the salt. APP_NAME hashes the own package, never the
reference package. This direct branch includes neither a Constellation number
credential nor a GMS IID token. Its format differs from the UPI V1 helper.

The raw bytes from the matching genuine `rcs_provisioning` VM snapshot first
become unpadded, unwrapped Base64URL (`efxp.a`, Android flags11). The V2 protobuf
contains only integer field1=2, string field2=that result and string field3=the
same raw salt; `ejtc.n` returns before adding V1's plaintext binding fields.
`ejwb` then encodes the protobuf with standard padded Base64 without wrapping
(flags2). That text is the value for multipart part
`client_authenticity_result_` plus the same GET's method ID. The matching carrier
token, cookies, request metadata and separate MLS nonce proof remain the
transport caller's responsibility.

Seven new offline regressions cover independent Python SHA-384/manual-protobuf
vectors, available-field omission, each session input and fresh salt, both
Base64 alphabets and outer padding, incomplete input and snapshot rejection,
and redacted diagnostics. The helper neither runs the VM nor verifies the
snapshot's provenance or acceptance; it makes no HTTP request. Its 64-KiB raw
snapshot bound is a host limit, not a recovered server limit. No live ACS request
was made for these tests. The response-derived retry gate in section16 remains
unchanged, and own-caller provisioning remains unproved.

## 20. Durable own-app MLS identity and labeled proof

The bounded normal participant path (`dbyq`, `dazb`, `daai`, `dbyn`, `dmoe`)
reads per-selected-SIM participant and device identities, locally creates missing
P256 pairs, persists both, and signs the ACS nonce. That path exposes no explicit
prerequisite enrollment RPC or Google caller-certificate check. Its normal
generator uses platform EC/secp256r1, public SPKI DER and a private scalar;
native labeled signing is separately corroborated by the earlier independent
signature checks. This does not establish global service eligibility or server
enrollment. `home_kds` comes from an injected Messages configuration flag, not
from the displayed key-generation response; no universal value is invented.

The [ordinary Android diagnostic](../../tools/android-checkin-probe/README.md)
now also includes independently written local MLS identity code. Its APK uses
ordinary platform JCA and protected app storage, with no GMS SDK or proprietary
native MLS implementation. It stores two distinct own P256 pairs atomically
before signing the caller's nonce, then rereads and validates them. This private
store uses PKCS8/SPKI rather than copying the reference's private-scalar layout.
Both public/private pairs receive fixed-domain consistency checks; corrupt,
partial, mismatched or incorrectly scoped records fail closed. Inspection creates
no identity or ACS nonce proof, though it performs those local consistency checks.
Explicit signing uses the RFC9420 MLS1.0 label prefix and variable-length framing
for `ACS_Participant_Key_Proof`; it signs nonce text, not the DG challenge or salt.

The same-signer update preserved the app's independent check-in credentials.
Initial inspection found no MLS identity. The first explicit sign persisted
both pairs, reread them and verified a synthetic-nonce signature. After stopping
that process, separate inspection found the identity ready without creating keys
or an ACS nonce proof. A second fresh process signed a different synthetic nonce
with the same persisted identity and no creation. Both keypair continuity
checks passed. Only enums, booleans and byte counts left instrumentation; no
private keys, public keys, fingerprints, signatures, binding tags or nonce values
were exported by the diagnostic.

The lab controller checked the owned phone and unchanged selected subscription,
ICCID, slot and default data subscription before and after operations. It used
root only for read-only SIM inventory and supplied a private binding tag to the
APK. That setup is not an ordinary-app SIM-discovery capability. The phone still
had microG installed; a physical no-GApps/no-microG test remains open.

Pure tests cover RFC9420 length boundaries, durable-record decoding, corruption
and same-curve key mismatches; an integration regression rejects instrumentation
failure even when ADB exits successfully. Source reviews caught and resolved
both missing pair-consistency validation and that host failure-propagation bug
before installation. The public minimal build has compile/DEX checks and identical
MLS Java sources; the tested private APK additionally contains the VM diagnostic.

No enrollment, carrier, ACS, VM bootstrap or check-in registration request was
made by this MLS probe. Its output explicitly reports enrolled=false and
attestation_verified=false. This is the local persisted-identity/proof boundary,
not an admitted RCS session. The next live attempt still needs a fresh authorized
ACS session, genuine VM materials and selected-SIM authentication, while honoring
section16's retry gate. A later source audit found typed long value 2 as the exact
compiled default for home-KDS flag 45670222 in reference build 324451063. The normal
provider passes it unchanged to the decimal query field. This supports explicit
reference-default configuration, not a universal value, current server assignment
or evidence of independent-client enrollment. The private source trace is
`static/rcs_runtime/own-home-kds-contract.md`.

Private evidence: `static/rcs_runtime/ordinary-mls-identity-contract.md` and
`standalone-checkin-probe/mls-lifecycle-summary-20261019.json`, with private
build/controller/run artifacts beside them. Live app-private keys remain only on
the phone.

## 21. Signed VM material retention and observed ten-second cache lifetime

The ordinary own-app host now retains the exact RSA-authenticated envelope,
matching inline VM APK/bytecode, and private context/receipt metadata when the
signed save/expiry policy permits it. Pinned microG source treats omitted save as
allowed, explicit false as unsaved, and positive expiryTimeSecs as a duration from
storage, with exclusive expiry. The own cache additionally requires the same
package/check-in identity, flow/version/fingerprint, boot and nondecreasing wall
and elapsed clocks. Both clocks must remain before expiry. Rereads verify the
original signed bytes again; a corruption checksum does not authenticate local
metadata against the owner or root. minWait/maxWait remain unconsumed fields with
unresolved units in the bounded source.

Executable provenance covers both the APK and its embedded native library. The
observed vendor loader may load an existing sibling `lib<selector>.so` without
checking its content. The host therefore authenticates the APK with real apksig
verification and the vendor certificate pin, validates its root library selector
and ARM64 ELF entry, and stages the exact APK/library in a new exclusive private
directory. Files are read-only, the completed directory is non-writable, and both
hashes are checked before and after execution. No shared old library is reused.
The five-argument vendor constructor and its GMS_CORE enum remain unchanged.

Actual phone observations on 2026-10-19:

- Same-signer version4 update preserved own check-in credentials and both MLS
  identity roles; the initial inspection made no request and found no cache.
- One separately journaled normal factory operation returned HTTP200 with
  449218 decoded bytes and no Retry-After. The original one-off bootstrap journal
  was preserved. Signature, save/expiry eligibility, private persistence/reread,
  APK/native provenance, initialization, an opaque 28456-byte snapshot and close
  all succeeded. No snapshot or private key bytes were exported.
- A later fresh-process snapshot stopped at EXPIRED without HTTP or VM loading.
  A same-signer version5 diagnostic update preserved the same identities and
  reported the signed cache duration as **10 seconds**, again with no request.
  This establishes retention and expiry enforcement, not successful cached VM
  execution in a second process. The fresh operation's private reread succeeded.

The ten seconds are the material-cache duration; they are not an established
proof-acceptance lifetime. The inspected SDK checks cache eligibility when
creating a handle, rather than on every snapshot of an initialized handle.
Future authorized ACS work must keep the genuine create/init/snapshot path in
the actual transaction. Receipt timestamps must not be refreshed to revive this
expired record. Both permanent fetch journals remain intact; there is no retry,
identity reset or fallback fetch in response to the expired-cache result.

The [public Java helpers](../../tools/android-vm-materials/README.md) are exact
copies of the tested bounded codecs/native-entry inspector. Independent public
compilation and synthetic checks cover 385 wire/signature, 782 cache and 42
native-archive rejection cases. Host build checks also retain the check-in/MLS
selfchecks. Source review covered the host, controller, manifest, cache and
native staging. The public helpers alone neither build the private Android
harness nor perform network/VM execution.

Private evidence: `static/carrier-static/own-vm-cache-policy.md`,
`static/carrier-static/actual-vm-dependencies.md` and
`standalone-checkin-probe/vm-session-lifecycle-summary-20261019.json`, with frozen
version4/version5 source/build/controller artifacts beside it. The phone still
has microG installed; physical no-GApps portability, server attestation
acceptance, provisioning, registration and Google Messages exchange remain open.

## 22. Rust direct ACS transaction context

`AcsSession::direct_challenge(&DirectParameters)` now implements the recovered
direct HTTP sequence independently of the UPI path. It returns either an opaque
WAP configuration or a challenge that holds exclusive session access. Carrier
authentication happens afterward: consuming `bind_carrier` attaches the genuine
selected-subscription temporary token and creates one salt. The resulting bound
context supplies the own-package V2 VM map, Java-style trimmed MLS nonce and
RFC9420 signing bytes. Its consuming `provision` locally verifies participant-key
possession and sends at most one POST. Neither the carrier token nor supplied VM
bytes acquire a provenance/attestation verdict from this API.

Both requests preserve the configured ACS path, actual cached version/state,
configured SMS port, optional selected-SIM identifiers and caller-formatted own
metadata. The query token stays empty; the carrier temporary token appears only
in the multipart body. The initial authenticity advertisement is absent on POST.
The two parts have the exact source-backed UTF8 text MIME type and no filename;
the proof part name uses the unchanged GET method ID. The POST includes all three
MLS query fields and an explicit caller routing value. Optional instance-ID and
provision-ID branches remain unsupported; model formatting/selected length limits
are supplied by the caller. The current host 10s connect/20s overall timeouts are
stricter than the reference 20s connect/60s read limits.

The same GET's JIBE value and full Cookie header are frozen alongside its
method/challenge, normalized nonce and immutable caller parameters. Cookie changes
before submission fail. A review found that the first implementation could reuse
a prior GET's jar cookie when another challenge omitted Set-Cookie. A failing
two-GET regression reproduced it. The recovered native entry clears cookies;
the bounded Rust implementation instead requires fresh applicable state before
the GET. The same issue was reproduced for initial UPI with an older cookie
scoped only to `/provision`; a shared guard checks both GET and proof paths.
Generic stateful initial/number-based operations keep their cookie semantics.
Creating a new HTTP session does not reset host journals or real service waits.

Common ACS transport now explicitly disables reqwest 0.13.5's default protocol
retries and stops on any Retry-After header, including HTTP200. Existing numeric
delta-seconds remain available in `Error::Http`; HTTP dates/invalid/empty values
have no parsed duration but still stop before the next step. This intentional
shared policy also applies to UPI and the generic ACS probes. It is not a retry
schedule or a reason to ignore an unknown wait.

Synthetic tests cover configured non-root paths, metadata/state/port values,
identifier omission, exact multipart framing and both encoding layers, salt/map
coupling, private Debug, owned-key signatures and wrong nonces, unsafe method
names, stale/missing/ambiguous cookies, exclusive context ownership, Java nonce
trimming that preserves NBSP and the separate DG challenge, opaque WAP handling,
HTTP200 wait headers, redirects and service rejections. Both stale-cookie fixes
have failing-before/passing-after regressions. All traffic in these tests is
loopback; no carrier, verification, VM or ACS backend request was made.

Private source contract: `static/carrier-static/direct-acs-http-contract.md`,
anchored to the same Messages324451063 artifact. This is preparation for the
next authorized own-client transaction. Android VM/carrier integration, actual
provider admission, registration, Google Messages exchange and physical vanilla
ROM portability remain open.

## 23. Ordinary Android Rust/JNI proof and TLS integration

On 2026-10-19 an independently signed version 6 update of the existing lab APK
preserved its check-in record and both persisted MLS identities. An ordinary
own-UID instrumentation worker loaded only the existing SIM-scoped identity;
missing, partial or invalid state fails without creation or replacement. The
host still used read-only root SIM inventory to bind this lab operation. That
does not establish ordinary-app subscription discovery or carrier authentication.

The real Rust crate and a small private JNI host compiled for
`aarch64-linux-android` with matching official Rust 1.99.1 compiler/standard
libraries and NDK 27.0.12077973, API 29. The system's Arch compiler could not consume
the official target metadata, so the matching toolchain stayed in the private
research directory; system Rust was unchanged. The combined APK retained the
previous app signer and data rather than reinstalling or registering again.

Rust chose a fresh synthetic nonce longer than 64 bytes and synchronously called
Java's new `MlsIdentity.signParticipantProof(byte[])` on the existing identity.
Only participant SPKI DER and DER ECDSA signature arrays crossed JNI inside that
app process. Private keys and their serialization stayed in Java/private storage.
The new pure `acs::verify_mls_participant_proof` uses the same bounded verifier as
direct/UPI submission, without requiring HTTP or a fabricated routing parameter.
It independently accepted the genuine signature and rejected an altered nonce.
Two fresh processes passed, with own check-in/MLS continuity verified before and
after each operation. Diagnostic output contained fixed codes/booleans only.

Android HTTPS required runtime packaging beyond a successful Rust build:

- `rustls-platform-verifier 0.7.1` needs initialization with the actual own
  application Context/classloader/JavaVM before TLS. JNI environments remain on
  the calling thread; the verifier attaches its own threads through that VM.
- Its pinned Android 0.2.0 Cargo shim contains no Java implementation. The
  matching Maven AAR was pinned to upstream archive commit
  `1aa691352a5e0c215210dfc9a3c2f2078639dc91` and verified before packaging.
- The AAR's three Java classes require Kotlin runtime classes despite its POM
  declaring no dependency. Installed Kotlin stdlib 2.2.10 covered all 13 referenced
  classes and 17 exact method descriptors. D8 included the complete stdlib and
  companion. The upstream network-security resource was compiled/linked into
  the own manifest, retaining its narrow CA-revocation cleartext allowances and
  base cleartext prohibition. No custom trust anchors or permissive verifier
  were introduced.

The second process then completed one bounded GET to the public HTTPS control
`https://example.com/`, returning 200 through the initialized Rust/Android
platform verifier. Redirects and automatic retries were disabled. This verifies
the packaged TLS path for that control, not carrier routing or an ACS session;
an invalid-certificate runtime control was not performed. TLS dependencies may
log certificate errors; the fixed JNI result policy does not promise that all
dependency logging is suppressed.

These checks made zero carrier, ACS, VM-material or new check-in registration
requests. Existing SDK attempt journals and the expired signed VM cache were
untouched. The physical phone still had microG installed. No-GApps portability,
independent admission, registration and Google Messages exchange remain unproven.
Private source/build provenance and all three update/test outcomes are retained
in `standalone-checkin-probe/rust-host-lifecycle-summary-20261019.json` under the
platform audit directory; no key, proof, credential or private capture is a fixture.

## 24. Cached VM callback and protected-data retention

The version 7 own-APK update adds a direct-V2 callback for an existing verified
material record. It validates the exact seven required hashed fields, optional
IMSI/IMEI, own Context/ordinary UID/worker, existing check-in identity, own signer
and the cache's signed envelope/context/boot/receipt clocks/TTL. Missing or
authenticated nonREADY cache state yields a bounded typed reason. It has no
fetch, old-envelope recapture, journal reset or automatic fallback operation.

The shared `DirectVmBoundary` lifecycle returns raw snapshot bytes only after
close, APK/native rehash and the final unsupported-callback check. Nested cleanup
runs the latter checks even when close throws. Any failure wipes the snapshot;
an error prefix or changed output after close also fails. The existing synthetic
instrumentation path uses this same lifecycle and discards its raw bytes. The
cached callback passes the caller's exact validated map rather than substituting
the diagnostic's synthetic APP_NAME/probe_nonce map.

The real Rust JNI negative control built seven synthetic V2 fields with the
actual own Context package and omitted unavailable IMSI/IMEI. Java validated the
map, then the actual callback rejected the existing signed cache with EXPIRED.
The test requires that typed reason, one callback, seven fields and no returned
snapshot; an unrelated JNI exception cannot count as success. No fresh VM
material request or READY callback execution occurred. This proves the boundary
and refusal path, not a genuine challenge-bound snapshot or admission.

Review also strengthened the lab's data-retention evidence. Earlier checks
established valid stored identities and pair consistency, without comparing an
independent before/after record baseline. The version 7 controller now compares
the complete regular-file set and SHA256 manifests of the protected files
directory entirely on-device. Neither contents nor digests return to the host.
Before/after update and callback comparisons both passed, including check-in,
MLS, material-cache and attempt records. Root performs only this evaluation
comparison and selected-SIM inventory; the APK still runs with its ordinary UID.
Unique root-only comparison files are removed afterward. Synthetic device tests
detected changed bytes, added files and symlinks, and verified cleanup after
uncertain capture completion. This lab helper is not a shipping dependency.

Pure Java tests include 31 direct-map/lifecycle rejection cases; the private
controller includes 18 strict-result cases and six device-fixture cases. Frozen
version 7 sources, native build provenance, APK identity and actual update/control
results are retained in `standalone-checkin-probe/vm-bridge-lifecycle-summary-20261019.json`.
Existing bootstrap/fetch journals and the expired ten-second cache remain intact.

## 25. Source-backed SMS OTP route and its availability gap

The retained legacy ACS client has a route that does not call SIM AKA:
an actual received provisioning SMS leads to a same-base HTTPS GET with uppercase
`OTP` and the saved cookies. It does not repeat initiation metadata or send a
carrier temporary token. Initial IMSI/MSISDN requests, selected mobile-network
header enrichment, privacy/consent gates and policy selection remain separate
requirements. A server requiring IMSI still needs an authorized identifier source.
The default SMS role's identifier access is distinct from ICC authentication.

When the selected configuration enables proactive HTTP-GET DroidGuard, the OTP
step requires a genuine V1 operation binding the own app, same logical session
and JIBE cookie. Its headers carry the URL-safe raw snapshot and fresh salt;
this is not the direct V2 multipart wrapper. The optional MLS proof signs the
JIBE_ACS_COOKIE value as-is using ACS_Participant_Key_Proof. Query fields are
`participant_public_key`, `signed_acs_data` and explicit `home_kds`, rather than
`participant_key_signed_nonce`. Conditional native branches can omit DG or MLS;
they do not establish that the provider accepts those omissions.

Text SMS extraction uses the selected configured regex and first nonempty
capture group. A positive configured data-SMS port instead consumes the complete
concatenated UTF16 payload. There is no universal six-digit code rule. The host
must associate the actual received subscription and session, preserve the code
without numeric conversion/trim and enforce its deadline. The compiled local
OTP wait is 360000ms; it is not a server expiry. A separate misleadingly named
cache flag defaults to 30 but its consumer uses MINUTES, not seconds. No automatic
cached-code replay is implemented here.

The reference can enter its waiting state after an HTTP 200 configuration parse
failure; this is a client transition, not an explicit server OTP offer. A new
client must not label malformed configuration, a direct DG nonce/challenge or
an invalid version 0 response as an OTP offer. No genuine associated OTP has been
observed for this subscription. Current PDV evidence likewise selected TS43 or
no pending method, without a server-selected SMS challenge. Policy flags and
method selection must remain truthful; this is not a way around retry gates.

The historical minimal discovery profile omitted GMS and selected direct TS43
off and UPI disabled, which permits legacy selection. It had manual-number input
disabled, a text-SMS pattern, port0 and discovery OTP timeout10s. That last field
is distinct from the separately consumed local wait flag above. The recorded
native profile with installed GMS selected direct TS43 and UPI without ACS
fallback; its OTP/manual-input fields were not projected. These profiles cannot
be merged or treated as fresh. Omitting actually installed GMS was a routing
simulation, not physical no-GApps or own-client admission evidence. A genuinely
GMS-free client needs its own truthful configuration and supported route.

The private source note records exact methods and evidence. A normalized REA
engine identity differs from the freshly verified pinned APK identity; the cause
remains unresolved. Independent raw-DEX inspection of the pinned APK confirmed
critical class/method/field references and timeout constants/units, without
independently reconstructing every decompiler branch. Treat the full flow as a
bounded implementation lead, not completed protocol parity or runtime success.
No new carrier/ACS/verification request or SMS send accompanied this audit.

## 26. Fresh VM factory and Android input refusal

The private Android harness now has a fresh-material factory for a future direct
transaction. Before recording intent or using the network, it validates the
actual own Context, ordinary UID, stored check-in and own APK signature. It also
checks the map's package/session/salt/version hashes against the real own package,
logical session and exact salt exposed by `DirectBoundChallenge`.

The factory accepts only its own live HTTPS response, verifies the signed bytes,
and retains the genuine receipt clocks, boot and context internally. It has no
caller-envelope or receipt-time import API and never opens the expired cache.
Fresh current-operation use is distinct from later cache eligibility: signed
`save` and TTL fields do not establish a running handle's lifetime. Unknown
signed wait units remain unresolved. The existing checked execution lifecycle
handles snapshot, close, artifact verification and failure wiping.

This lab factory permits one durable attempt total, including after success.
Any attempt record blocks another UUID; completion is diagnostic only. Old
experiment journals remain unchanged. Offline regression checks cover a failure
after completion, overlapping entry and symlink refusal. The version 8 APK
packages the factory and a fixed negative control; it has no valid-input
instrumentation operation. All 16 Java sources compile, and the pure history
and lifecycle selfchecks pass.

On the phone, Rust constructed seven synthetic V2 fields with the actual own
package and called the real Java factory with a deliberately invalid salt.
Success requires the exact typed binding exception, reported as native result7;
an arbitrary JNI error cannot pass. The factory refused before check-in/config
access, history creation or HTTP. The ordinary-UID worker also ran the history
selfchecks inside its own cache, exercising file locking, exclusive writes,
file force, symlink refusal and refusal after a completed attempt. A thread-local
StrictMode policy prohibited network use during this control. The genuine
factory history remained absent before and after, preserving its future attempt.
This does not test the factory's receipt write, directory fsync or power-loss
durability.

The same-signer APK update and subsequent control both passed the on-device exact
protected-file comparison. Existing check-in, MLS, material-cache and attempt
records stayed unchanged; test cache fixtures and lab comparison files were
removed. The private build/native provenance and both outcomes are retained in
`standalone-checkin-probe/fresh-vm-guard-lifecycle-summary-20261019.json`.
No new SDK, carrier or ACS request occurred. Valid-input factory execution, the
actual bound ACS transaction, accepted provisioning and ordinary-app carrier
authentication remain open.

## 27. Own-client transaction host and Android subscription control

The private version 12 APK builds the actual Rust direct transaction into the own
Android harness. A single Rust context holds the ACS challenge and cookies,
waits for newly obtained carrier authentication, signs the exact bound MLS
nonce with the existing own key, and supplies that same binding's salt and map
to the fresh VM factory before its single POST. It has no saved-token reader,
expired-material fallback or caller-supplied snapshot. WAP bodies remain private
and opaque; receiving one does not establish accepted provisioning.

The host checks the selected subscription before the GET, during HTTP and the
carrier wait, and before VM execution and POST. The vendor VM call is synchronous;
only the surrounding checks fence a detected subscription change. Completed
HTTP errors retain their actual status and numeric retry interval. Java callback
errors preserve their original exception while clearing temporary JNI buffers,
including malformed or oversized proof arrays. Fifteen checks against the
actual shared Rust cleanup module passed on a desktop JVM with checked JNI.

Before VM execution and POST, the updated host also requires a bounded,
same-session acknowledgment from the coordinator. Its exact wire format passed
Java/Python interoperability checks and rejected 221 malformed replies. The
private file reader rejects nonregular files without blocking on FIFOs. The
positive Android acknowledgment path remains unexecuted.

The same-signer APK compiles 21 Java sources and five Rust source modules with
the existing dependencies. Android compilation and the pure input, wire,
cache, history and lifecycle checks pass. The frozen native sources and Cargo
inputs are recorded with the build. A separate offline subscription control
registers the ordinary app's listener, observes its initial callback, polls for
two seconds and unregisters. Its runner preserves the existing check-in and MLS
records and reports only an exact fixed schema; 55 result-parser checks pass.

Version 12 is installed on the same owned phone. The update and both offline
controls passed their exact on-device protected-file comparisons. The Rust/Java
negative control again returned the required typed refusal and left genuine
factory history absent. The ordinary-UID subscription control received its
initial callback, stayed stable for 17 polls and completed listener cleanup.
Its worker prohibited network use. Root staged an immutable own-app metadata
file separately from the existing records, with the known future not-before
floor intact; the app received the normal `READ_PHONE_STATE` permission.
These checks establish callback and cleanup behavior, not response to an actual
SIM change or ordinary-app access to IMSI, IMEI or carrier authentication.

An earlier publication control failed as an ordinary app while its exact APK
helper passed under root ART. App publication now uses atomic
`renameat2(RENAME_NOREPLACE)`, replacing hardlinks, which
[AOSP forbids for untrusted apps](https://android.googlesource.com/platform/system/sepolicy/+/refs/heads/main/private/app_neverallows.te).
The ordinary-UID control passed publication, directory fsync and preservation of
existing files, dangling symlinks and directories on collision. This capability
check also runs before a real GET. Root-published replies can still temporarily
have two links; only handoff polling defers that state within its existing
deadline, and consumes data at one link. Strict record reads remain unchanged.

A pure carrier adapter uses the configured service and actual SIM/device values
with truthful own app metadata and User-Agent; 42 synthetic checks pass. A pure
dispatch gate retains the evidenced earliest time plus later native and HTTP
waits, requires current native retry metadata, and rejects missing evidence,
unparsed retry instructions and clock rollback. Neither component establishes
server acceptance. A separate live read-only Phone-process control now compares
the selected subscription, IMSI, IMEI, GID, operator, ICCID and device metadata
against the private baseline on the device. Every comparison and temporary
resource cleanup passed; only booleans were returned. It performed no AKA or
HTTP. Frida startup and Java-bridge initialization failures were resolved before
that successful control.

The gated coordinator joins this inspection, fresh carrier authentication and
the new host acknowledgments. Reviewed failure checks cover metadata expiry,
known versus unknown HTTP waits, pending publication and independent cleanup.
They remain separate from the unexecuted network transaction. The latest observed
native cache moved its retry time to October 20, 2026 at 22:15:12 UTC; the durable
coordinator retains this later floor and must also honor any subsequent native
or HTTP wait. Carrier AKA through the privileged Phone process remains a
laboratory dependency, separate from ordinary-app capability.
No new SDK, carrier or ACS request accompanied this source, build and control work.

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
   Section15 adds a completed native paired request that still returned an
   invalid configuration. The normal MLS provider now produces a verified
   synthetic proof and persists its keys locally. Its coupled server request
   remains untested and must respect both the prior response's freshness and
   a fresh native retry deadline. The ordinary-caller SDK control in section 16
   still depends on microG and does not satisfy the vanilla-ROM requirement.
   Section17 adds an independent ordinary-app check-in identity; section18 adds
   direct own-context VM execution. Provider admission and physical portability
   without GApps/microG still need proof.
   Section19 supplies the recovered direct V2 Rust binding/encoding; connecting
   it to a fresh genuine own-context snapshot and authorized ACS session remains
   untested. The section18 one-off host retained only its APK; section21 now
   retains the signed envelope/bytecode association, but the observed ten-second
   cache lifetime expired before another process could execute it. Keep genuine
   VM creation and snapshot within the future authorized ACS transaction.
   Section22 now supplies the Rust direct request/context path; it still needs
   the real Android host's carrier, VM and persisted MLS operations in that run.
   Section23 now proves the Rust/Java persisted signer boundary and a separate
   packaged platform-TLS control on the ordinary APK. The real one-transaction
   host still needs carrier authentication and fresh VM material within the
   authorized exchange; the expired ten-second cache cannot supply it.
   Section24 adds the cached-only VM callback and proves its EXPIRED refusal,
   with exact on-device record retention across the own APK update. READY
   callback execution remains open. Section25 identifies a source-backed OTP
   alternative; actual policy selection and a genuine associated SMS are missing.
   Section26 adds the fresh-material factory's Android filesystem and typed
   invalid-input control; valid execution and the bound transaction remain untested.
   Section27 installs the same-context transaction host with coordinator
   acknowledgments, verifies its offline subscription control, and proves the
   separate live SIM inspection and ordinary-app atomic publication. Recheck
   artifact, SIM and latest native/HTTP evidence before a request allowed by
   the retained gates; the positive bound exchange remains untested.
   Section20 adds durable own-app participant/device identity and locally verified
   labeled proofs; using that identity in an accepted ACS request remains open.
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
