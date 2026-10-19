# Ordinary Android check-in probe

An independently signed, self-targeted diagnostic APK registers its own Google
check-in identity using platform HTTPS and real accessible `android.os.Build`
fields. INTERNET is its only permission. It has no GMS/microG, Google Messages,
account, phone/SIM, root, shared-UID or third-party-library dependency.

This is a Task 2 authentication experiment. Check-in credentials do not establish
DroidGuard acceptance, RCS provisioning, SIP registration or message delivery.
An additional self-targeted MLS diagnostic tests durable own participant/device
keys and labeled nonce signing. Neither diagnostic establishes server enrollment.

`inspect` is the default and reads only this app's private state. Explicit
`register` makes one initial gzip/protobuf HTTPS POST with androidId0,
fragment0, version3, required nested build and one empty account cookie. It omits
unavailable identifiers, clientId, OTA certificates, account tokens and reference
app identities. Its User-Agent identifies this probe.

Before opening a connection, it locks and durably writes an attempt marker in
its own app data. Existing credentials or a prior attempt prevent another POST.
There is no retry/reset/refresh/export operation. Both returned fixed64 fields
must be nonzero; their exact bits are saved atomically and reread before success.
No identifiers, tokens, raw responses or exception messages enter the result.
Returned intents and settings are skipped rather than applied.

The marker survives process death, not app-data deletion or uninstall. A hosting
harness must retain its own durable registration-intent marker before dispatch
to preserve the single-attempt rule across those events. Do not clear data or
uninstall to retry an uncertain registration. The recorded lab harness uses both
host and app markers.

HTTPS uses platform certificate/hostname checks, fixed-length request streaming,
redirects disabled, 15-second connect/read timeouts and a 45-second body deadline.
Wire input is capped at 64 KiB, decompressed input at 256 KiB. Malformed lengths,
unsupported wire types, wrong known-field types and duplicate known singular
fields fail closed. Supported unknown fields, including repeated ones, are
skipped. A host must also bound execution; a blocked write/read can outlive the
body deadline. Stopping this app cannot undo a request already received remotely.

## Build and test

Use JDK9 or newer, SDK platform API36 and build tools. Set `ANDROID_JAR` to
`android.jar`, `BUILD_TOOLS` to the SDK build-tools directory, and `PROBE_BUILD`
to a private directory outside Git. From this directory:

```sh
umask 077
mkdir -p "$PROBE_BUILD/classes" "$PROBE_BUILD/dex"
javac --release 8 -classpath "$ANDROID_JAR" -d "$PROBE_BUILD/classes" CheckinWire.java StandaloneCheckinProbe.java MlsIdentity.java StandaloneMlsProbe.java
java -ea -cp "$PROBE_BUILD/classes" org.rcsrs.standalonecheckin.CheckinWire
java -ea -cp "$PROBE_BUILD/classes" org.rcsrs.standalonecheckin.MlsIdentity
jar cf "$PROBE_BUILD/classes.jar" -C "$PROBE_BUILD/classes" .
"$BUILD_TOOLS/d8" --lib "$ANDROID_JAR" --min-api 29 --output "$PROBE_BUILD/dex" "$PROBE_BUILD/classes.jar"
"$BUILD_TOOLS/aapt2" link -I "$ANDROID_JAR" --manifest AndroidManifest.xml -o "$PROBE_BUILD/unsigned.apk"
zip -j "$PROBE_BUILD/unsigned.apk" "$PROBE_BUILD/dex/classes.dex"
"$BUILD_TOOLS/zipalign" -f 4 "$PROBE_BUILD/unsigned.apk" "$PROBE_BUILD/aligned.apk"
```

Wire selfchecks cover high-bit fixed64 values, truncation, malformed/duplicate
credential fields, unknown fields, varint overflow, gzip corruption/decompression
bombs, size limits and first-registration field selection. They contact no service.

Set `PROBE_KEYSTORE` and `PROBE_KEY_ALIAS` to your own private signing identity.
Create it once with `keytool -genkeypair` if needed and retain it for updates.
Signing prompts for its password:

```sh
"$BUILD_TOOLS/apksigner" sign --ks "$PROBE_KEYSTORE" --ks-key-alias "$PROBE_KEY_ALIAS" --out "$PROBE_BUILD/probe.apk" "$PROBE_BUILD/aligned.apk"
"$BUILD_TOOLS/apksigner" verify "$PROBE_BUILD/probe.apk"
```

Set `ADB` to the SDK binary and `ANDROID_SERIAL` to the explicitly selected
device. Installation targets user0 and preserves any existing package by failing
instead of replacing it. Inspect before dispatching a registration:

```sh
"$ADB" -s "$ANDROID_SERIAL" install --user 0 -t "$PROBE_BUILD/probe.apk"
"$ADB" -s "$ANDROID_SERIAL" shell am instrument --user 0 -w -r -e mode inspect org.rcsrs.standalonecheckin/.StandaloneCheckinProbe
```

For a fresh inspected installation, create the host's durable intent marker,
then invoke the same instrumentation with `-e mode register`. Bound the host
command separately; the lab used 90 seconds and force-stopped only this own APK.
Keep registration markers and credentials intact afterward.

## Result and observed scope

One Bundle string, `standalone_checkin`, contains only schema_version1,
mode/stage/status enums, own_context, ordinary_uid, attempt_recorded,
credentials_present, network_attempted, http_code and response_bytes. Successful
registration requires all three attempt/credentials/network flags, HTTP200,
positive response length and durable private storage. Instrumentation code1 means
`failed` or `http_rejected`; code0 covers the other diagnostic statuses. A host
must check the command exit code, single terminal instrumentation code, absence
of failure markers and the result status together.

On 2026-10-19, the independently signed lab APK completed one POST with HTTP200
and a 374-byte decoded response containing both issued credentials. A separate
inspection after force-stop found them persisted and issued no request. The
test ran on a custom ROM with microG installed; this probe did not call it.
Physical testing on a ROM without GApps/microG remains open. Repeated-unknown
field hardening was verified offline after that runtime baseline.

## Local MLS identity diagnostic

`StandaloneMlsProbe` requires the same app's persisted own check-in identity.
Its `inspect` default reads the selected identity without creating it or signing
an ACS nonce. It performs discarded fixed-domain signatures to validate both
stored public/private pairs. Explicit `sign` creates participant and device
P256 pairs only for a fresh scope, persists both, rereads them, then signs and
verifies the nonce with RFC9420 SignWithLabel and label
`ACS_Participant_Key_Proof`. It uses ordinary platform JCA, with no Google SDK,
proprietary native MLS code or network request. The private store uses SPKI and
PKCS8; this is the probe's own format, distinct from the reference's private scalar.

Supply `-e binding_tag` with a private stable 64-character lowercase-hex tag for
the verified selected SIM. The host must verify that same SIM before and after
every operation; the APK does not discover it or obtain SIM permissions. The lab
used root only for read-only host-side SIM inventory, which is not a proven
ordinary-app SIM-binding solution. For `sign`, also supply `-e nonce_base64` with
canonical standard padded Base64 of the actual UTF8 ACS nonce, not the separate
DroidGuard challenge. Empty/control-containing/malformed text and nonces over
16 KiB fail closed. Inspect rejects a nonce argument.

The host must durably record first-use intent before dispatch, reject a missing
identity when a prior creation intent exists, and retain the same own app signing
key/data across updates. Existing or partial/corrupt state is never replaced.
Both roles have private/public baselines and pair-consistency checks; file locking
serializes writers, and file/directory fsync plus atomic rename precede ACS nonce
signing. No reset, rotation, proof export or key export operation is provided.

Bundle key `standalone_mls` contains schema_version1, mode/stage/status enums,
own_context, ordinary_uid, own_checkin_present, identity_present,
identity_created, identity_reloaded, participant_continuity, device_continuity,
signature_verified, attestation_verified=false, enrolled=false, nonce_bytes and
signature_bytes. The signature flag/counts concern only the explicit ACS nonce
proof; internal consistency checks do not set them. `failed` uses instrumentation
code1; `no_identity`, `ready` and `signed` use code0. A volatile key can have been
created before persistence fails; that failure is not a usable stored identity.
Check the full instrumentation result, status, terminal code and host exit code.
No private/public key, fingerprint, signature, tag or nonce value leaves the result.

On 2026-10-19 the same-signer lab update preserved own check-in credentials.
Initial inspection found no MLS identity. The first sign persisted both pairs and
verified a labeled proof for a synthetic nonce. After force-stop, inspection found
the same stored identity; another fresh process verified a different synthetic
nonce without creating keys. Private key bytes were not read by the host or
exported. The actual APK also contained the separate private VM diagnostic; this
directory's minimal combined build has compile/DEX checks, not a separate install.
The phone still had microG installed. Server enrollment, a no-GApps ROM test and
accepted RCS provisioning remain open.

Pure selfchecks cover literal RFC9420 short/64/16384-byte length vectors,
record round trips, truncation/corruption/baseline/tag/curve errors, same-curve
participant and device pair mismatches, and wrong-content/raw-nonce signature
rejection. All test keys are synthetic; no app state is loaded by selfchecks.

## Provenance

The bounded codec is independently written from microG's
[checkin.proto](https://github.com/microg/GmsCore/blob/ec206605ab97ada8369dade98ce822880f716033/play-services-core-proto/src/main/proto/checkin.proto).
Transport behavior was compared with its original
[CheckinClient](https://github.com/microg/GmsCore/blob/ec206605ab97ada8369dade98ce822880f716033/play-services-core/src/main/java/org/microg/gms/checkin/CheckinClient.java).
The pinned source has Apache-2.0 headers; [LICENSE](LICENSE) retains the license
and the codec header records attribution and changes. No VM binary, API key,
profile builder or other app's credentials are included.
The independently written MLS diagnostic follows the bounded local first-use
contract described in [the research record](../../docs/research/gapps-bootstrap.md).
