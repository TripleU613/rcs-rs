# Community RCS research — 2026-10-20

The strongest next experiment is completing the existing Constellation/UPI
verification path, with the corrected carrier-response encoding, and separately
establishing which registration transport an accepted configuration authorizes.
This is a research recommendation, not a newly demonstrated working connection.

The latest local direct-ACS experiment reached HTTP 400 on its initial GET.
It did not request carrier authentication, VM material, or a proof POST.
Consequently that result does not establish that a submitted proof was rejected.
The native-schedule override did not fix admission.

## What the public evidence actually establishes

The [microG bounty](https://github.com/microg/GmsCore/issues/2994) is currently
titled $14,999 and remains open. Its target is Google Messages running with
microG on a locked-bootloader device without root. That is a useful reference
milestone, but does not itself deliver our independent, ordinary-app Rust client.

| Primary source | Reported observation | Implication |
| --- | --- | --- |
| [benwaffle, August 14, 2025](https://github.com/microg/GmsCore/issues/2994#issuecomment-3186377513) | Research used a Tello SIM; native provisioning went to a T-Mobile Jibe ACS. | Especially relevant carrier precedent; not evidence about our specific line. |
| [benwaffle, March 6, 2026](https://github.com/microg/GmsCore/issues/2994#issuecomment-4010086482) and [scope clarification](https://github.com/microg/GmsCore/issues/2994#issuecomment-4012870217) | Reported an RCS message on a microG ROM; implementation supported Google Messages through phone verification. | Historical device success exists, but Google Messages still supplied the messaging client. |
| [bounty sponsor, May 6](https://github.com/microg/GmsCore/issues/2994#issuecomment-4390002020) | Reported 30 users, over 10 carriers, one device model, SMS and TS43 flows, persistent operation. | A more useful reference than unexecuted implementation claims; independently reproducing it is still necessary. |
| [sponsor, July 13](https://github.com/microg/GmsCore/issues/2994#issuecomment-4960882053) and [tester, July 15](https://github.com/microg/GmsCore/issues/2994#issuecomment-4983070859) | HTTP400 regression; a tester still saw it after restoring Basic Integrity. | A generic integrity-check result does not isolate our HTTP400 cause. |
| [July 20 recovery](https://github.com/microg/GmsCore/issues/2994#issuecomment-5026138505), [July 26 Verizon report](https://github.com/microg/GmsCore/issues/2994#issuecomment-5085824623), [August 1 recurrence](https://github.com/microg/GmsCore/issues/2994#issuecomment-5152908682) | Some installations recovered; another later failed again. | Historical success is not a current universal recipe. |

The implementation lineage is opstic's
[Constellation #3359](https://github.com/microg/GmsCore/pull/3359) and
[Asterism #3360](https://github.com/microg/GmsCore/pull/3360).
The [October integration #3851](https://github.com/microg/GmsCore/pull/3851)
explicitly distinguishes build/test results from outstanding real-device
acceptance. Likewise [#3784](https://github.com/microg/GmsCore/pull/3784)
and [#3808](https://github.com/microg/GmsCore/pull/3808) contain useful corrections
but do not establish their complete end-to-end acceptance.
The GitHub API currently reports all five PRs open and unmerged. Source heads
checked: #3359 `b7d91f0a`, #3360 `2a680646`, #3784 `ec206605`,
#3808 `223f91fe`, #3851 `e31a421f`. No branch was built or installed here.

## Transport must be tested, not assumed

[benwaffle's September 29 experiment](https://github.com/microg/GmsCore/issues/2994#issuecomment-3344527320)
forced Google Messages away from Tachygram and observed SIP403, as in the
independent Python client. His
[February explanation](https://github.com/microg/GmsCore/issues/2994#issuecomment-3855319771)
separates carrier ownership verification from client admission.
This is a reported experiment, not proof that all Jibe deployments prohibit SIP.

[phhusson's scripts](https://github.com/phhusson/rcs_experimentations)
provide a small OTP/configuration/refresh/SIP reference. Their author reported
[configuration and file-upload success, with SIP still unresolved](https://github.com/microg/GmsCore/issues/2994#issuecomment-3193700763).
[Hirohumi's Rust client](https://github.com/Hirohumi/rust-rcs-client)
offers reusable standard-RCS functionality, with documented messaging-mode
limitations; its README does not demonstrate Google Jibe interoperability.

The independent client must follow the actually provisioned transport.
Investigate Tachygram registration alongside the configuration decoder; do not
build a large SIP layer on the assumption that any returned XML authorizes it.
The older Samsung CompositeToken path remains a comparative lead, not an
accepted alternative for our app identity.

## Comparison with this checkout

The [existing provider record](provider-access.md) already establishes:

- RCS consent lookup succeeded.
- Initial Sync previously returned a genuine TS43 challenge.
- Carrier EAP-AKA and temporary-token acquisition succeeded in the root lab.
- A historical Proceed used the wrong protobuf tag for the full carrier JSON;
  Rust now uses field 2, but the corrected fresh flow was blocked by verification
  throttling.
- The Google number credential and credential-bearing UPI ACS exchange remain
  missing.
- The installed reference microG previously lacked the native Constellation
  service. That recorded observation requires a fresh package check before any
  future installation or reference-client test.

Therefore Constellation is not a newly discovered API for this project. The
actionable change in emphasis is to finish its partly successful transaction,
instead of repeatedly varying the direct ACS request.

## Next bounded experiment

1. Inspect the retained UPI attempt records and current host inputs. Preserve
   the same owned identities and distinguish its verification throttle from
   direct ACS scheduling. An old reported 24-hour recovery is not a guaranteed
   server reset deadline.
2. Prepare a single fresh Sync → offered TS43 challenge → carrier JSON →
   corrected Proceed transaction. Preserve both session IDs, the original
   verification/context, and the actual key-ack state. Do not substitute a
   synthetic SMS challenge or an expired earlier challenge.
3. Require VERIFIED and an actual returned number credential before the UPI
   ACS handoff. Record the stage and bounded, private response evidence at any
   refusal; do not interpret an outer successful RPC as verification.
4. From an accepted configuration, identify and test the authorized registration
   transport. A successful two-device RCS send/reply is the milestone.

A source-built opstic-derived microG reference control on this phone could help
separate line/environment failure from Rust implementation differences. Replacing
the installed microG may require signer/ROM changes and is a separate operation;
no replacement, data clearing, permission broadening, or third-party APK execution
was performed for this research.

The issue's 704 public comments were retrieved through the GitHub API because
the rendered page hides most discussion. Technical conclusions above use original
researchers' reports and implementation sources. XDA, GrapheneOS, Sailfish and
Reddit searches supplied leads, not proof of a portable working client. Some
older benwaffle repository links are currently unavailable.

## Fresh UPI experiment — October 20, 15:39 UTC

Executed one authorized Sync after the October 16 attempt, using the same
retained IID, check-in identity, public key, subscriber and unexpired
backend-issued attestation token. Only the two request session IDs were renewed.
The read-only Phone-context comparison confirmed the physical device and SIM;
its temporary resources were cleaned up before Sync.

Google returned a decoded verification record with state NONE (1), reason
THROTTLED (1), and status code 8. No number credential or pending challenge was
returned. Carrier authentication, Proceed, UPI provisioning and registration
therefore did not run. No automatic retry or identity reset was performed.

The [subsequent throttle investigation](verification-throttle-2026-10-20.md)
recovered a roughly one-hour global Sync retry instruction that the brief
decoded output omitted. The per-record retry value is zero. Neither value
establishes when the underlying verification quota will recover.

The private one-shot runner's synthetic response guards passed, and the current
Rust example was rebuilt with 12 focused request/transport tests passing.
These checks validate local handling, not provider admission.

This result leaves the corrected Proceed path untested live. Four elapsed days
did not establish server quota recovery. A known-working reference-client
control on the same line is now more informative than another identical Sync:
it can distinguish a line/provider problem from this independent request's
identity or protocol context. It has not yet been performed.
