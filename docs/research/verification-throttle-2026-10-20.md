# Constellation Sync THROTTLED investigation — October 20, 2026

The retained response really reports verification-resource exhaustion. It also
contains a roughly one-hour **global Sync retry delay**, which the earlier
analysis missed by examining only the per-record retry field. This is a client
scheduling instruction, not a guarantee that the verification quota recovers
after one hour.

## Fresh offline evidence

Independently decoded four retained raw protobuf responses using a minimal
`protoc` schema reconstructed from retained GMS 26.37.37 descriptors. No new
provisioning requests were sent. All four have state NONE (1), unverified reason
THROTTLED (1), record status 8, and the exact status message:

> syncVerif failed: generic::resource_exhausted: verification resource is exhausted due to too many recent verifications or attempts.

| Capture | Response timestamp, UTC (seconds shown) | Global retry delay, milliseconds | Record retry delay, milliseconds |
| --- | --- | ---: | ---: |
| rust-attempt05 | October 16, 07:02:34 | 3,599,617 | 0 |
| rust-attempt06 | October 16, 08:08:05 | 3,599,573 | 0 |
| rust-attempt07 | October 16, 14:30:40 | 3,599,669 | 0 |
| upi-resume-20261020 | October 20, 15:39:42 | 3,599,607 | 0 |

The latest global timestamp pair points to approximately 16:39:42 UTC
(12:39:42 EDT). Native code schedules relative to the difference between the
two timestamps, added to local receipt time, rather than trusting that absolute
timestamp as the local deadline. Fresh response timestamps are consistent with
fresh server responses, rather than accidentally re-reading the October 16 file.

The October 16 08:08 and 14:30 attempts and October 20 attempt were already
separated from their preceding captured attempts by more than an hour. Thus
respecting this delay alone has not cleared the underlying verification refusal.
These captures do not account for all possible background requests.

## Why the two retry values differ

Retained decompiled artifact evidence:

- `jowy.gK`: SyncResponse field 2 is a `joxr` timestamp pair.
- `joxc.gK`: UnverifiedInfo field 2 is a separate `joxr` pair.
- `joxr.gK`: fields 1 and 2 are Timestamp messages.
- `brwb.a/b`: convert each timestamp to milliseconds, then subtract second
  from first. The tiny negative record differences truncate to zero.
- `bqzr`, result construction around line 841: exposes the record difference
  as `retry_after`.
- `bqzr`, Sync handling around lines 1192–1214: uses the root difference to
  store a next-Sync scheduling timestamp, subject to existing state and flags.
- `jcvk.gK`: record status code is field 1 and message is field 3. This is not
  a `google.rpc.Status` with an embedded `RetryInfo` in that field.

The current Rust wire decoder preserves raw response bytes but does not expose
either retry pair. Consequently the brief decoded console output omitted this
useful scheduling evidence. This investigation does not change that API.

The earlier private ground-truth note's conclusion about no useful future delay
was incomplete: it described the record pair only. There is still no recovered
**quota reset deadline**, but there is a positive global retry instruction.

## Public reports

- A [March 1 GrapheneOS report](https://discuss.grapheneos.org/d/1353-using-rcs-with-google-messages-on-grapheneos/2251)
  contains the same Sync exhaustion message with genuine Google Play services,
  following RCS disabling and Messages data clearing. The report was available
  in indexed forum text; direct rendering intermittently required JavaScript.
  The error alone therefore does not diagnose a malformed independent client.
- [opstic, June 8](https://github.com/microg/GmsCore/issues/2994#issuecomment-4649739578)
  describes recovery as usually about 24 hours in their experience.
  [0xNoushad, May 7](https://github.com/microg/GmsCore/issues/2994#issuecomment-4397932826)
  reports roughly three days after deliberately repeated toggling. These are
  observations, not a documented service contract.
- A [June 8 original log](https://github.com/user-attachments/files/28709094/log.txt)
  shows repeated UPI VerifyPhoneNumber RESOURCE_EXHAUSTED failures;
  the [June 9 follow-up](https://github.com/microg/GmsCore/issues/2994#issuecomment-4663743560)
  indicates verification subsequently passed. Other installation/storage state
  changed, so this does not isolate the timer.
- A [separate GetVerifiedPhoneNumbers report](https://github.com/microg/GmsCore/issues/2994#issuecomment-4454978579)
  explicitly identifies a consumer-project requests-per-minute quota. That is
  a different RPC; its quota scope cannot be assigned to this Sync error.
- [Google's phone-number verification documentation](https://support.google.com/android/answer/7521240)
  describes periodic device verification. This explains why absence of manual
  scripts alone does not establish silence. It does not establish that this
  phone made such requests, or that they extend this particular throttle.

## What remains unknown and what follows

Neither the captured status nor these reports identifies whether the exhausted
resource is keyed by number, SIM, device identity, account, network address,
project, or a combination. They do not establish a sliding reset timer, nor a
reliable recovery through identity rotation, data clearing, or a VPN.

The next useful diagnostic is an audit of retained/native verification activity
during the presumed quiet period, followed by a controlled reference-client
comparison if feasible. Another immediate identical Sync would not resolve
those uncertainties. Direct ACS HTTP400 and its independent retry state must
remain separate from this Constellation result.

Raw captures and the temporary forensic schema remain outside Git. Checked
schema mappings against retained descriptors and native arithmetic, compared
all four captures, and exercised a millisecond-boundary assertion. No phone
settings, identities, schedules, or production code were changed; no live retry
or reference-client comparison was performed.

## Authorized retry — October 21, 02:34 UTC

Ran one fresh same-identity Sync at 02:34:17 UTC (October 20, 22:34 EDT),
more than ten hours after the preceding response. The live SIM checks passed.
The result again had NONE (1), THROTTLED (1), status 8, and the identical
verification-resource-exhaustion message. The global retry difference was
3,599,572 milliseconds. No pending challenge or credential was returned;
carrier authentication and Proceed did not run. No automatic retry was enabled.
This confirms that waiting beyond the advertised one-hour Sync interval did
not clear the refusal for this attempt; it does not identify the quota scope.

## Follow-up: reported recovery methods

The strongest new lead is inthewaves' Bell recovery report in the
[GrapheneOS discussion](https://discuss.grapheneos.org/d/1353-using-rcs-with-google-messages-on-grapheneos/2221).
After reporting the exact Sync resource-exhaustion error, the researcher waited
about a day and then saw NONE/invalid-verification-method. They subsequently
turned RCS off, disabled Google's automatic phone-number verification, and
turned RCS back on, without clearing data or rebooting. Logs showed incoming
SMS (MT) verification reaching VERIFIED. The intervening state change matters:
this does not prove the toggle instantly clears a still-active quota. It was
Bell with genuine Play services, not our Tello/microG/Rust environment.

A separate [firsthand VPN report](https://discuss.grapheneos.org/d/16919-vpn-block-connections-disconnects-rcs)
resolved disconnection by disabling Android's block-connections-without-VPN
setting: Tailscale excluded Messages from its tunnel. This concerns Android
routing, not evidence that disabling the desktop VPN clears Sync throttling.
[Other firsthand network-change reports](https://www.reddit.com/r/GoogleMessages/comments/1vszt0g/verizon_rcs_not_working_fixed/)
describe enabling a VPN to restore registration, but do not establish the same
Constellation error or its quota scope.

Research priority: determine how the automatic-verification setting affects
consent/policy and MT challenge selection before translating this into our
client. Do not assume a local UI toggle maps to a known Rust request field,
or manufacture a challenge. No settings or account recovery factors were
changed and no additional provisioning request was sent for this research.

## Proxy experiment prepared — October 21

PDV Sync/Proceed now supports an explicit experimental HTTP CONNECT proxy via
`RCS_PDV_HTTP_PROXY=IP:port`. It accepts a socket address, not a URL or credentials.
An invalid value or failed proxy connection fails closed, with no direct fallback.
Origin TLS certificate and hostname verification remain enabled. Other API
transports are unaffected. The CONNECT exchange has a ten-second deadline and
an 8 KiB response-header limit.

Forty public ProxyScrape HTTP proxies were checked with public HTTPS traffic;
five passed. The selected `34.43.46.91:80` also passed a real Tonic connection
to the PDV origin with TLS/HTTP2, without sending a verification RPC.
This establishes transport connectivity only.

A private pinned copy of the client and same-identity one-shot runner is scheduled
by user timer `rcs-upi-proxy-20261021.timer` for October 21, 03:34:20 UTC
(October 20, 23:34:20 EDT), after the latest response's conservative one-hour
wait. It checks the live device/SIM, uses the coordinator lock, preserves prior
attempt captures, and stops after a failed Sync. A genuine pending TS43 challenge
can continue through the existing carrier/Proceed path. There is no retry loop
or proxy rotation. Scheduled execution is not a successful verification result.

## Proxy execution results — October 21

The timer fired at 03:34:20 UTC. The selected proxy failed at the TLS/HTTP2
transport stage; no response protobuf was received. The runner's `sync_sent`
flag indicates invocation, not confirmed server receipt.

At 04:42 UTC a replacement proxy, `141.144.206.124:1080`, passed the explicit
origin TLS connection test. A same-identity Sync through that proxy then returned
NONE (1), THROTTLED (1), status 8, with the same resource-exhaustion message.
No direct fallback was enabled. No challenge or credential was returned and
Proceed did not run. This network change did not clear the refusal; it does
not identify the quota key or prove all network changes would behave alike.

## Consent and method comparison — October 21, 14:38 UTC

A fresh same-identity GetConsent completed successfully and still reported RCS
CONSENTED (1). No SetConsent or Sync was performed during this check. The retained
backend attestation was still within its supplied expiry. This rules out missing
RCS consent in that observed response, not other provider admission requirements.

Current source from microG PR #3359 shows its verification settings switch writes
a local setting; `handleVerifyPhoneNumberRequest` checks it and throws a disabled
exception before the verification flow. This is not a known quota-reset RPC or
an incoming-SMS selector. Relevant source files are
`PhoneNumberVerificationPreferencesFragment.kt`, `ConstellationStateStore.kt`,
and `VerifyPhoneNumber.kt` under `play-services-constellation/core`.
The source was retrieved from the PR's file-specific pinned raw URLs.

A fresh read-only phone package inspection found microG version 0.3.17.252432.
The Constellation action appears in its dummy-service filter, which does not
establish a working implementation. The last 8,000 log lines contained no
verification-related records; this short tail cannot establish a multi-day
quiet period. Google Messages' retained `ejwu.k` also contains a configuration-
dependent fallback to non-UPI after non-retryable API failure. Thus the forum
recovery's MT log does not establish that Constellation itself cleared its quota.

The Rust CLI previously always supplied `mt_sms_token: None`. It now accepts a
private `mt_sms_token_file` for exactly 11 ASCII bytes from a real active Android
receiver, using the library's existing receiver metadata and validation.
No alternate policy, method override, manufactured token, or new SMS challenge
was submitted. Activating and observing a receiver remains necessary before
using this input in a live experiment.

## Additional identity experiments and Messages audit — October 22

The local audit note records RESOURCE_EXHAUSTED for the original identity,
PERMISSION_DENIED for two alternative registration contexts, and UNAUTHENTICATED
for an account-linked messaging registration. None produced a new Sync challenge.
Different registration scopes and different refusal codes do not establish that
fresh identities need an earlier successful Sync, nor that the throttle is keyed
only to the SIM. Those hypotheses remain unproven.

The same note records unverified number flags, an empty provisioning credential
and a pending retry state in the reference Messages installation. These observations
are consistent with incomplete registration. They do not prove that Messages and
our Rust request share a quota, or that its queued retries reached Constellation.
The native ACS worker and its waits must still be distinguished from UPI Sync.

There was no six-day quiet-period control: retained Rust attempts occurred on
October 20 and 21. Elapsed time since the original October 16 attempt cannot be
used as evidence of uninterrupted inactivity. No accepted provisioning or RCS
message exchange was demonstrated by the October 22 note.

Identifiers, account details, registration handles and private database extracts
are omitted from this public record. The retained backend attestation's recorded
expiry is October 24; any later experiment must check expiry before use.

## Same-identity retry — October 23, 03:23 UTC

One fresh direct Sync completed at 03:23:44 UTC (October 22, 23:23 EDT), after
the retained Sync waits had elapsed and with the original unexpired identity
inputs. Live device/SIM comparison passed. The older preflight initially stopped
because an existing lab instrumentation daemon prevented starting another copy;
the successful check reused that daemon only after checking it had no active TCP
client. Its own attachment, forwarding and generated outputs were cleaned up,
with all cleanup checks passing; the existing daemon was left running.

Google again returned NONE (1), THROTTLED (1), record status 8 and the identical
verification-resource-exhaustion message. The global retry difference was
3,599,592 milliseconds. No pending challenge or number credential was returned;
carrier authentication and Proceed did not run. No automatic retry was enabled.
The local preflight failures sent no Sync. Raw evidence remains outside Git.

## Accepted-versus-throttled request comparison — October 23

Compared the retained first successful Sync request/response with the first
throttled request using the independent protobuf descriptors. The successful
response had PENDING (2), status 0 and a TS43 challenge. The request differences
were renewed session IDs and their caller nonce, plus replacing the raw
`constellation_verify` proof with the backend-issued cached token.

The device/IID, public key, SIM association, policy, telephony and method data
matched between those two captures. The cached token in the first throttled
request is the token returned by the successful Sync and retained by the later
canonical identity. The original raw-proof script's IID hash also matches that
same identity.

Native code supports cached-token reuse until expiry, so this does not establish
that caching caused the throttle. Backend state changed between the attempts as
well. It does identify a concrete comparison for a future controlled experiment:
a newly generated genuine `constellation_verify` proof bound to `rpc=sync` and
the same IID, with the identity and policy preserved. Simply waiting another
hour or replaying the original old raw proof would not test that difference.

A native same-IID proof control was then attempted on the existing microG lab
host. It stalled without returning a proof. The host controller was terminated
and its owned ADB forward removed; the existing daemon and GMS process were
preserved. No new verification Sync was sent. This control does not establish
whether the native proof operation itself failed or its instrumentation stalled.
The proposed fresh-proof-versus-cache comparison remains unperformed.

### Fresh-proof control repaired and next experiment prepared

The instrumentation stall was traced to an unanswered Frida Java-bridge load
request in the new private controller. Supplying the pinned bridge fixed that
handshake. The native API then returned a new roughly 32 KiB proof for the same
IID and `rpc=sync`. An additional private-controller bound of 16 KiB rejected
that genuine result; it was corrected to the Rust library's existing 64 KiB
bound. These were controller defects, not evidence of a native proof refusal.
All attachment and forwarding cleanup checks passed after the successful native
return. This proof control sent no verification Sync.

A one-shot experiment is scheduled for October 23, 04:23:47 UTC, after the latest
Sync's conservative one-hour interval. It will generate another new proof just
before Sync, preserve the canonical IID/key/SIM/policy and use no cached token
for that Sync. If an accepted TS43 challenge supplies a new backend cache, that
new cache can authorize the existing carrier/Proceed continuation. An old raw
Sync proof will not be reused for Proceed. Missing follow-up attestation stops
the continuation explicitly. Source pins, live SIM comparison and owned resource
cleanup remain required. There is no retry loop or automatic identity rotation.

This establishes that the fresh-proof path is available. The provider's result
for the raw-proof-versus-cache experiment is still pending; quota recovery and
successful verification are not established by generating a proof locally.

### Fresh-proof experiment result — October 23, 04:23 UTC

The scheduled attempt completed at 04:23:57 UTC (00:23 EDT). It generated a
32,062-character native proof for the same IID and `rpc=sync`, configured the
identity with that raw proof and no cached-token input, and passed the live SIM
comparison. Proof-generation and metadata cleanup checks passed.

Google again returned NONE (1), THROTTLED (1), record status 8 and the same
verification-resource-exhaustion message. No challenge or credential was issued,
so carrier authentication and Proceed did not run. No further Sync was sent to
produce this update. Replacing the cached token with a new native proof did not
clear the refusal in this controlled attempt; the underlying quota scope and
admission cause remain unknown.
