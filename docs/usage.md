# Bootstrap and verification guide

These examples exercise the current research APIs. Live requests require
provider-admitted, caller-supplied inputs; local tests require none.


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
protobuf captures offline. They expose TS43 and incoming-SMS challenges and per-record failures,
retain exact verification/context bytes, and redact private fields in diagnostics.
They do not send verification requests or validate returned tokens. The decoder
has also been checked against the private pending, failed and throttled captures.

`verification::initial_sync` sends one initial verification request using genuine
SIM/caller facts. `verification::proceed_ts43_unsigned` submits a genuine full
carrier JSON response while preserving the original verification/context bytes.
It rejects public-key updates because signed follow-ups are not implemented.
Neither function retries automatically or treats outer RPC success as verification.
`InitialSync::mt_sms_token` must be `None` unless the host has a live SMS receiver:
an empty string selects ordinary SMS reception metadata; otherwise supply the real
Android app-specific token. The CLI omits receiver metadata by default. To use
a real active receiver, set `mt_sms_token_file` in the private session JSON to a
file containing exactly its 11 ASCII token bytes, without a trailing newline.
The CLI does not start a receiver or prove incoming delivery.
`verification::proceed_mt_sms_unsigned` submits one genuinely received matching
SMS body and originator for an actual pending MT_SMS challenge. It preserves the
original record and refuses key updates; the Android host still owns reception,
subscription/session association and cancellation. Google offering this method
to an independent caller remains unproven.
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

## Optional verification proxy

PDV Sync and Proceed support an experimental HTTP CONNECT tunnel:

```sh
RCS_PDV_HTTP_PROXY=127.0.0.1:8080 \
  cargo run --example verify_number -- sync /private/session.json /private/new-response.pb
```

The value must be an IP address and nonzero port, not a URL. Proxy authentication
and hostname resolution for the proxy are not implemented. Origin TLS certificate
and hostname checks remain enabled. Invalid configuration, connection failure or
CONNECT refusal stops the request; there is no direct fallback. Other API
transports are unaffected. An IP change does not establish that verification
quota has reset; retain response evidence and applicable retry waits.

The ignored connection test performs an actual TLS/HTTP2 connection but sends no
verification RPC. Run it explicitly only with a proxy you intend to test:

```sh
RCS_PDV_HTTP_PROXY=127.0.0.1:8080 \
  cargo test live_proxy_connects_with_origin_tls --lib -- --ignored
```

`AcsSession::upi_challenge` implements the recovered UPI challenge request.
Its context exposes the private DroidGuard input map and MLS signing bytes.
Supply a genuine platform result and an owned P-256 participant signature to
`UpiChallenge::provision`; it verifies the signature and sends one `/provision`
request. The context holds exclusive session access until consumed or dropped.
This path has synthetic wire and localhost transport coverage. A separate live
UPI challenge probe obtained a nonce/cookie; credential-bearing UPI provisioning
and service registration remain unverified.

`AcsSession::direct_challenge(&DirectParameters)` implements the separate direct
TS43 route. It returns either opaque WAP bytes or an owned challenge context.
After genuine selected-subscription carrier authentication, consume that context
with `bind_carrier(token)`. The resulting `DirectBoundChallenge` supplies the
private VM input map, its exact salt for in-process host binding checks, and the
trimmed MLS nonce/signing bytes. Keep that salt coupled to the same context; never
replace it or export it in diagnostics. Its consuming
`provision(raw_vm_snapshot, &MlsProof)` verifies the owned participant signature
and submits one multipart POST to the same configured path. VM execution and
carrier authentication remain the Android host's responsibility.

`acs::verify_mls_participant_proof(nonce, spki_der, signature_der)` also checks an
owned labeled signature without an HTTP exchange or routing configuration.
An ordinary Android lab APK has used this Rust function through JNI with its
existing Java identity and passed a separate platform-verified HTTPS control.
This establishes host integration, with admission and vanilla-ROM portability
still unproven; see the [integration record](research/gapps-bootstrap.md#23-ordinary-android-rustjni-proof-and-tls-integration).

Supply actual configuration version/state, SMS port, device type and already
formatted own-client metadata. Initial version/state/port0 are explicit inputs,
not universal defaults. This bounded direct implementation excludes optional
instance-ID/provision-ID branches. `home_kds` is explicit caller configuration;
reference build 324451063 has a compiled default 2, which is not an independent
client's enrollment or server assignment.

Initial direct and UPI exchanges require a fresh applicable cookie jar; UPI also
checks its separate `/provision` path. A previous GET's cookie cannot authorize a
new challenge that supplies none. Generic initial/number-based methods retain
their stateful cookie behavior. Keep request journals and service waits outside
the HTTP session; creating another session does not reset those obligations.
Any ACS Retry-After header stops the exchange, including on HTTP200. Only numeric
delta-seconds are returned as a duration; date/invalid/empty values still stop it.
ACS transport disables protocol retries and redirects. Its 10s connect/20s total
timeouts are host limits, not the reference client's 20s connect/60s read limits.

The direct Rust API has synthetic framing/signature and localhost transport
coverage. It has not yet submitted a live own-client ACS proof or established
accepted provisioning, registration or messaging.

`cargo test --all-targets` runs the synthetic protocol and localhost transport
checks. Formatting and strict Clippy also pass. No live credentials are needed
for these tests.

See [recovered GApps behavior](research/gapps-bootstrap.md) for artifact
identities, wire evidence, live checks and remaining blockers.
The [provider-access record](research/provider-access.md) separates this
subscription's UPI credential/provisioning path from Android single registration
and the carrier temporary-token route.

The [ordinary Android capability probe](../tools/android-admission-probe/README.md)
builds as a small self-targeted instrumentation APK without Google SDKs. It reports
permission gates and identifier availability without exporting subscriber values;
it neither changes the SMS role nor tests RCS registration.
