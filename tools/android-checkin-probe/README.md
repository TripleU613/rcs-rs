# Ordinary Android check-in probe

An independently signed, self-targeted diagnostic APK registers its own Google
check-in identity using platform HTTPS and real accessible `android.os.Build`
fields. INTERNET is its only permission. It has no GMS/microG, Google Messages,
account, phone/SIM, root, shared-UID or third-party-library dependency.

This is a Task 2 authentication experiment. Check-in credentials do not establish
DroidGuard acceptance, RCS provisioning, SIP registration or message delivery.

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
javac --release 8 -classpath "$ANDROID_JAR" -d "$PROBE_BUILD/classes" CheckinWire.java StandaloneCheckinProbe.java
java -ea -cp "$PROBE_BUILD/classes" org.rcsrs.standalonecheckin.CheckinWire
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

## Provenance

The bounded codec is independently written from microG's
[checkin.proto](https://github.com/microg/GmsCore/blob/ec206605ab97ada8369dade98ce822880f716033/play-services-core-proto/src/main/proto/checkin.proto).
Transport behavior was compared with its original
[CheckinClient](https://github.com/microg/GmsCore/blob/ec206605ab97ada8369dade98ce822880f716033/play-services-core/src/main/java/org/microg/gms/checkin/CheckinClient.java).
The pinned source has Apache-2.0 headers; [LICENSE](LICENSE) retains the license
and the codec header records attribution and changes. No VM binary, API key,
profile builder or other app's credentials are included.
