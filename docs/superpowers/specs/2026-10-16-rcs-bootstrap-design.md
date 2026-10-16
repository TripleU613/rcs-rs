# RCS bootstrap design

Date: 2026-10-16
Status: proposed for review

## Intended outcome

An open source SMS client can embed a Rust engine to register for RCS and
exchange messages with compatible clients, including Google Messages when the
provider admits the client. The first implementation milestone establishes
provisioning and registration. It must report the actual failure stage when
that cannot be completed.

This repository starts with the bootstrap milestone. A complete messaging engine
requires later capability discovery, messaging transport and delivery handling.
No UI, SMS database migration or root module belongs in this milestone.

## Evidence and limits

The locally inspected Google Messages build was
`messages.android_20220926_01_RC04.phone_dynamic`, APK SHA-256
`9238cb2d0da0cea7926f6d18d089a582f34f3a645d38f2049a22e0bd0bff31a2`.
Its `bdne.b` availability check uses `bdsf.f` to determine whether a nonempty
configuration URL is available. The observed failure occurs at that local check,
before a provisioning or registration attempt. The user-facing carrier error
therefore does not establish a server rejection.

This finding applies to that build and observed runtime state. It does not prove
the current Google client uses the same bootstrap or that the discovered ACS
accepts independent clients. Private device evidence remains outside this repo.

The existing Rust client has a `start_auto_config` entry point, a configuration
server model, provisioning XML handling and registration code. Its public
constructor also exposes platform callbacks and SIM/device identifiers. Its
manifest uses a sibling path dependency for `rust-rcs-core`. Before adoption,
check that it builds on Linux and that platform assumptions can be isolated.
Do not create an application-facing wrapper around an unverified dependency.

## Approaches

1. **Reuse the existing Rust protocol implementation.** Recommended: evaluate a
   pinned upstream revision and extend its bootstrap where necessary. This avoids
   rebuilding the protocol stack, but still requires a compatibility and logging
   audit and a live admission test.
2. Build a new stack. This gives control over the API but duplicates substantial
   SIP, provisioning and messaging work before reaching the current blocker.
3. Bridge Google Messages. This creates an app dependency and does not provide
   the independent embedded engine requested here.

## Bootstrap flow

1. Accept explicit carrier configuration or derive a standard ACS candidate from
   validated MCC/MNC. Preserve two- versus three-digit MNC identity; pad only where
   the relevant network naming rule requires it. A candidate is not authorization.
2. Follow the provisioning flow supported by the selected provider. Surface
   requests for cellular routing, user verification or SIM authentication to the
   host platform; do not manufacture credentials or return success for an
   unimplemented authentication method.
3. Parse and validate the returned configuration, including service authorization,
   expiry and the IMS parameters required for registration. Distinguish invalid
   configuration from a legitimate disabled-service response.
4. Perform authenticated SIP registration using provisioned identities and
   authentication material. Report registered only after server confirmation.
5. Return a structured result identifying discovery, provisioning, authentication
   or registration failure, with retry timing when supplied by the server.

The portable core owns protocol processing. The Android adapter supplies access
to the selected subscription, cellular network binding and supported SIM/SMS
authentication facilities. An ordinary SMS app may lack permissions required by
a particular provider flow; record the exact unavailable capability. Merely
becoming the default SMS app does not guarantee provisioning access.

## Trust boundaries

Use verified TLS for requests carrying credentials or identifiers. If a standard
flow begins with HTTP, its initial request must not contain secrets. Do not
forward authentication material across arbitrary redirects. Bound response size,
XML processing and retries. Honor server backoff and cancellation. Keep secrets
out of Debug output, errors, fixtures and logs. Do not import another app's
private tokens as the library's authentication mechanism.

Keep the existing SMS application's send behavior unchanged until RCS is ready.
Transport selection and user-visible fallback are later app integration work;
avoid automatic duplicate sends during bootstrap testing.

## Scope reached by the first implementation

- A buildable Rust library and minimal bootstrap example.
- Reused upstream code where its build and behavior are verified; preserve its
  Apache-2.0 license and notices for any copied or adapted source.
- Validated configuration discovery and provisioning input/output.
- Platform authentication boundary and registration result.
- Synthetic provisioning and registration fixtures with tests for success,
  rejection, malformed input, expiry, retry handling and credential redaction.
- README explaining the implemented provider flow and precise remaining limits.

No crate name reservation, publication, JNI packaging, messaging UI, group chat,
attachments, MLS encryption or blanket carrier compatibility claim is included.

## Acceptance criteria

Offline: tests exercise each implemented state transition, invalid configuration,
authentication failure and retry handling. Formatting and clippy checks pass.
Unsupported flows produce explicit errors rather than simulated progress.

Live: obtain authorized configuration and an authenticated registration on the
test subscription. Record only redacted stage/status evidence. If admission or
platform access blocks this, the milestone remains incomplete and the exact
response or missing capability is documented.

Product interoperability is a subsequent check: capability discovery and one
text message in each direction with Google Messages, with transport confirmed
as RCS. An SMS baseline, HTTP response or successful registration alone cannot
satisfy that check.

## References

- [GSMA RCC.07 client specification](https://www.gsma.com/solutions-and-impact/technologies/networks/gsma_resources/rcc-07-rich-communication-suite-advanced-communications-services-and-client-specification/)
- [GSMA RCC.14 device configuration](https://www.gsma.com/solutions-and-impact/technologies/networks/gsma_resources/rcc-14-service-provider-device-configuration/)
- [Tello RCS support](https://tello.com/help_center/service-issues-troubleshooting/how-can-i-enable-rcs-messaging-on-my-device)
- [Existing Rust client](https://github.com/Hirohumi/rust-rcs-client)
- [Existing Rust core](https://github.com/Hirohumi/rust-rcs-core)
