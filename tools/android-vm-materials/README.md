# Signed VM material codecs

Java8 helpers used by the ordinary own-app VM experiment. They implement
bounded create-request/response protobuf, RSA-SHA256 verification of the exact
signed response bytes, a private reusable-material record, and inspection of
the observed vendor APK's root native-library resource, plus a direct-map and
owned-operation boundary. They perform no HTTP and supply no VM, APK signature
verifier, attestation verifier or RCS admission. The lifecycle helper invokes
the caller's supplied operation; its checks do not establish proof provenance.
No VM binary, API configuration, captured material or app credentials are included.

From this directory, with `VM_CLASSES` set to an empty private build directory:

```sh
umask 077
mkdir -p "$VM_CLASSES"
javac --release 8 -d "$VM_CLASSES" DroidGuardWire.java VmSignedResponse.java VmMaterialCache.java VmNativeArtifact.java DirectVmBoundary.java
java -ea -cp "$VM_CLASSES" org.rcsrs.standalonecheckin.VmSignedResponse
java -ea -cp "$VM_CLASSES" org.rcsrs.standalonecheckin.VmMaterialCache
java -ea -cp "$VM_CLASSES" org.rcsrs.standalonecheckin.VmNativeArtifact
java -ea -cp "$VM_CLASSES" org.rcsrs.standalonecheckin.DirectVmBoundary
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

`DirectVmBoundary.directInputs` defensively copies the exact direct-V2 map:
seven required fields and optional IMSI/IMEI, each a lowercase SHA384 hex value.
Nulls, duplicates, unknown/reserved keys and malformed values fail. It neither
rehashes values nor replaces `APP_NAME`. The Rust caller must use the real own
Android package and the same binding/challenge/session for the later submission.

`DirectVmBoundary.execute` owns one supplied operation through construct, init,
snapshot and close. Artifact verification and an unsupported-callback check run
even if close fails. Raw bytes return only after those checks and final output
validation; failures wipe any returned snapshot. The host must perform genuine
signature/context/cache verification and make close a no-op when no handle was
constructed. This helper provides no loader, network fallback or cache refresh.
Selfchecks exercise successful ordering and failures at each lifecycle stage,
including close errors, post-close unsupported callbacks and changed output.

The ordinary Android lab host now exposes a cached-only in-process callback using
this boundary. Its JNI negative control passed with the authenticated expired
record: no fetch, initialization or snapshot was used. READY callback execution
remains untested. See the [runtime record](../../docs/research/gapps-bootstrap.md#24-cached-vm-callback-and-protected-data-retention).

Wire/cache semantics were compared with pinned Apache-2.0 microG sources:
[droidguard.proto](https://github.com/microg/GmsCore/blob/ec206605ab97ada8369dade98ce822880f716033/play-services-droidguard/core/src/main/proto/droidguard.proto),
[NetworkHandleProxyFactory](https://github.com/microg/GmsCore/blob/ec206605ab97ada8369dade98ce822880f716033/play-services-droidguard/core/src/main/kotlin/org/microg/gms/droidguard/core/NetworkHandleProxyFactory.kt),
and [DgDatabaseHelper](https://github.com/microg/GmsCore/blob/ec206605ab97ada8369dade98ce822880f716033/play-services-droidguard/core/src/main/kotlin/org/microg/gms/droidguard/core/DgDatabaseHelper.kt).
Attribution is retained in source headers; see the adjacent check-in probe's
[Apache-2.0 license](../android-checkin-probe/LICENSE) and the
[runtime research record](../../docs/research/gapps-bootstrap.md).
