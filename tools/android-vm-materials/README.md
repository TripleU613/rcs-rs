# Signed VM material codecs

Four Java8 helpers used by the ordinary own-app VM experiment. They implement
bounded create-request/response protobuf, RSA-SHA256 verification of the exact
signed response bytes, a private reusable-material record, and inspection of
the observed vendor APK's root native-library resource. They perform no HTTP,
VM execution, APK signature verification, attestation verification or RCS admission.
No VM binary, API configuration, captured material or app credentials are included.

From this directory, with `VM_CLASSES` set to an empty private build directory:

```sh
umask 077
mkdir -p "$VM_CLASSES"
javac --release 8 -d "$VM_CLASSES" DroidGuardWire.java VmSignedResponse.java VmMaterialCache.java VmNativeArtifact.java
java -ea -cp "$VM_CLASSES" org.rcsrs.standalonecheckin.VmSignedResponse
java -ea -cp "$VM_CLASSES" org.rcsrs.standalonecheckin.VmMaterialCache
java -ea -cp "$VM_CLASSES" org.rcsrs.standalonecheckin.VmNativeArtifact
```

These selfchecks use synthetic protobuf/ZIP inputs and ephemeral test keys. They
make no device or network calls and do not open an app's state. The lab's
independently signed Android host and transport remain private research harnesses;
these helpers alone do not build that APK or an operational RCS client.

`VmSignedResponse.verifyAndDecode` requires the caller's configured RSA SPKI
trust anchor. It verifies the original envelope data before decoding. Re-encoding
a parsed message is not signature verification of the original bytes.

`VmMaterialCache.capture` permits saving when signed `save` is absent or true,
requires positive relative `expirySecs`, and retains the exact authenticated
envelope together with local context/receipt metadata. `writePrivate` writes only
to a caller-supplied private stream. `readPrivate` repeats RSA verification and
requires the same own context and boot, no clock rollback, and both wall and
elapsed clocks strictly before expiry. The checksum detects accidental
corruption; it does not protect local metadata from the owner or root. The caller
must bind its real package/check-in identity, fingerprint, flow and compatibility
version, protect the record, and publish it atomically with fsync. Never replace
identity or refresh receipt times to revive an expired record. `Result.validitySeconds` exposes only the signed nullable lifetime, including
for expired records; an ineligible result still exposes no reusable Entry.
Ineligible caching does not by itself prohibit using a fresh response for its current operation.

`VmNativeArtifact.inspect` requires an already authenticated APK. It validates
the observed `library.txt` → `lib<selector>.so` selection and ARM64 ELF shape;
it is deliberately limited to this observed artifact family. It provides neither
APK trust nor a universal ABI loader. The Android host separately verifies the
APK signature/vendor pin and stages the APK and exact selected native bytes in
a fresh exclusive private directory, with read-only files and before/after
hashes. This prevents the vendor loader from silently reusing an unrelated
existing sibling library.

Cache misses never trigger HTTP in these helpers. Retain attempt journals and
actual service retry gates in the host. The signed minWait/maxWait fields are
preserved; their units/consumption were not recovered in the bounded source.

Wire/cache semantics were compared with pinned Apache-2.0 microG sources:
[droidguard.proto](https://github.com/microg/GmsCore/blob/ec206605ab97ada8369dade98ce822880f716033/play-services-droidguard/core/src/main/proto/droidguard.proto),
[NetworkHandleProxyFactory](https://github.com/microg/GmsCore/blob/ec206605ab97ada8369dade98ce822880f716033/play-services-droidguard/core/src/main/kotlin/org/microg/gms/droidguard/core/NetworkHandleProxyFactory.kt),
and [DgDatabaseHelper](https://github.com/microg/GmsCore/blob/ec206605ab97ada8369dade98ce822880f716033/play-services-droidguard/core/src/main/kotlin/org/microg/gms/droidguard/core/DgDatabaseHelper.kt).
Attribution is retained in source headers; see the adjacent check-in probe's
[Apache-2.0 license](../android-checkin-probe/LICENSE) and the
[runtime research record](../../docs/research/gapps-bootstrap.md).
