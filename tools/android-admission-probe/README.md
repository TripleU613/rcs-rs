# Ordinary Android admission probe

Self-targeted instrumentation only: no UI, third-party dependencies, Google SDK,
shared UID, SMS receivers or SMS permissions. Package `org.rcsrs.admissionprobe`,
version 1 (`0.1.0`), min API29, target API36.

`AdmissionProbe` checks matching instrumentation/target identity and ordinary
application UID and rejects system or updated-system applications before reading.
Success returns instrumentation code0 and one Bundle string, `rcs_admission`, containing the exact JSON contract in
`check_result.py`. Invalid identity or setup failure returns code1 and `{}`.
There is no diagnostic logging or exception-message output.

The result contains actual APK signing-certificate SHA1, version, SDK, UID,
default-SMS boolean, permission and feature booleans, carrier-privilege availability,
and present/absent/denied/unavailable statuses for IMSI, IMEI and own number.
Subscriber strings are inspected only for emptiness and never serialized.
The own-number read uses `TelephonyManager.getLine1Number`; absence does not prove
there is no assigned number. Reported feature flags do not establish working IMS.

No ICC authentication, verification, network request, SMS operation, or shell
permission adoption occurs. Normal phone permissions are declared for standard
runtime grants. The network permissions are normal permissions declared only
to measure their gates. Signature/privileged permissions are checked without
requesting or obtaining them.

## Validation

Validate the checker and a privately captured instrumentation result:

```sh
python3 tools/android-admission-probe/check_result.py --self-test
python3 tools/android-admission-probe/check_result.py /private/path/instrumentation-output.txt
```

The checker accepts one JSON object or standard
`INSTRUMENTATION_RESULT: rcs_admission=...` output, prints no supplied JSON, and
requires a non-default-SMS normal UID. It rejects raw subscriber fields, extra
keys, invalid identities and types.

## Manual SDK build reference

Use an installed SDK platform API36 or newer, SDK build tools, and JDK9 or newer
with `--release 8`.
Set `ANDROID_JAR` to that platform's `android.jar`, `BUILD_TOOLS` to its build-tools
directory, and `PROBE_BUILD` to a private directory outside Git. From this source
directory, these standard commands build an unsigned APK without Gradle:

```sh
umask 077
mkdir -p "$PROBE_BUILD/classes" "$PROBE_BUILD/dex" "$PROBE_BUILD/generated"
"$BUILD_TOOLS/aapt2" link -I "$ANDROID_JAR" --manifest AndroidManifest.xml --java "$PROBE_BUILD/generated" -o "$PROBE_BUILD/unsigned.apk"
javac --release 8 -classpath "$ANDROID_JAR" -d "$PROBE_BUILD/classes" AdmissionProbe.java
"$BUILD_TOOLS/d8" --lib "$ANDROID_JAR" --min-api 29 --output "$PROBE_BUILD/dex" "$PROBE_BUILD/classes/org/rcsrs/admissionprobe/"*.class
zip -j "$PROBE_BUILD/unsigned.apk" "$PROBE_BUILD/dex/classes.dex"
```

Set `PROBE_KEYSTORE` and `PROBE_KEY_ALIAS` to an existing private signing key.
For a new project, create it once with `keytool -genkeypair` and reuse it for
subsequent builds. Signing prompts for its password; do not put passwords in
shell arguments. Set `ADB` to the SDK's `adb` binary and `ANDROID_SERIAL` to the
chosen device. Align, sign, install and run from this source directory:

```sh
"$BUILD_TOOLS/zipalign" -f 4 "$PROBE_BUILD/unsigned.apk" "$PROBE_BUILD/aligned.apk"
"$BUILD_TOOLS/apksigner" sign --ks "$PROBE_KEYSTORE" --ks-key-alias "$PROBE_KEY_ALIAS" --out "$PROBE_BUILD/probe.apk" "$PROBE_BUILD/aligned.apk"
"$ADB" -s "$ANDROID_SERIAL" install -r --no-incremental "$PROBE_BUILD/probe.apk"
"$ADB" -s "$ANDROID_SERIAL" shell pm grant org.rcsrs.admissionprobe android.permission.READ_PHONE_STATE
"$ADB" -s "$ANDROID_SERIAL" shell pm grant org.rcsrs.admissionprobe android.permission.READ_PHONE_NUMBERS
"$ADB" -s "$ANDROID_SERIAL" shell am instrument -w org.rcsrs.admissionprobe/.AdmissionProbe > "$PROBE_BUILD/result.txt"
python3 check_result.py "$PROBE_BUILD/result.txt"
```

These are standard runtime grants; the instrumentation does not adopt shell
permissions. Keep keys, APKs and captured output outside Git. To remove the probe,
run `"$ADB" -s "$ANDROID_SERIAL" uninstall org.rcsrs.admissionprobe`.

This non-default-SMS probe cannot establish default-SMS-only access: it neither
holds nor qualifies for that role. Results on this microG/custom-ROM phone do not
establish behavior on a vanilla or stock ROM. Backend/API-key admission is a
separate boundary; this probe sends no requests to test it.
