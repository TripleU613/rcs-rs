All verification fixtures use independently encoded synthetic values. They contain
no real SIM identity, registered IID, usable credentials, device captures, or tokens.
Schema sources: original GMS 26.37.37 descriptors jowy/joxi/joxf/jowe/joss/jott/jotp/
jots/jotk/joxc and client bqzr. The custom result status descriptor jcvk confirms
code field1 and message field3; field2 is retained without assigning a meaning.

- `verification-pending.bin`: exact embedded Verification with state field2=2,
  challenge field4 -> container field2 -> Challenge.method2=11 and TS43 field12.
  TS43.context1 is exactly `0807120400ff8000`, including unknown binary contents.
  URL2 uses carrier.example.test; params3 exercises all 15 known parameter fields.
  AcquireTemporaryToken5 -> operation1 contains synthetic name/type/targets and
  an unknown field99. The SIM association contains test IMSI 001010000000001.
- `verification-sync-pending.bin`: response field1 -> result Verification1 plus
  custom status2 (explicit code1=0, opaque field2=`generic`, message3 synthetic).
  Response header3 contains an unknown string field2. No meaning is assigned.
- `verification-proceed-failed.bin`: Proceed response Verification1 has state2=1,
  unverified-info field9 with reason1=2 and method3=11. The opaque timestamp-pair
  field2 contains equal synthetic values; the decoder derives no expiry or delay.
- `verification-sync-throttled.bin`: state2=1, unverified reason1=1, custom status
  code1=8 and synthetic recent-attempt text. Outer response decoding succeeds while
  the per-record failure remains visible.

Challenge-container fields3/4 are unknown and are **not** interpreted as TTL or flags.
No returned state/token is validated as proof that a phone number is verified.

- `sync-request.bin`: independent initial request encoding, synthetic caller/SIM
  facts and proof, zero slot explicitly present, one IMSI request and SHA-256
  caller-session/IMSI nonce. Header version is GMS version code divided by 1000.
- `proceed-request.bin`: original `verification-pending.bin` preserved byte for
  byte, opaque context unchanged, full synthetic carrier JSON in
  ChallengeResponse9 -> TS43.temporary3 -> **TemporaryResponse.string2**,
  two synthetic history strings in TS43 field5 and a synthetic cached proof.
  Original GMS `joty` declares its only string as field2; field1 was an earlier
  reconstruction error. These request fixtures use the original descriptor,
  not a round trip through the Rust encoder under test.

- `read-numbers-request.bin`: independently encoded signed read-only request
  (`brad`, `joxl/joxn/joxp`): request session1, credentials2 with synthetic IID1,
  synthetic DER signature2 and Timestamp3 (1700000000 seconds, 123000000 nanos),
  packed selection3=2 (RCS), caller4 with oldest-certificate SHA1 in standard
  padded Base64 field1, package2 and nonce3. The signature is the synthetic
  ASN.1 sequence `3006020101020101`, not a usable credential or ownership proof.
  DroidGuard is omitted per the recovered read API default; Sync's proof/cache
  encoding does not belong in this request.
- `read-numbers-response.bin`: response repeated field2 contains phone1
  `+10000000000`, timestamp2={seconds1:1}, synthetic `id_token`3 and unknown numeric
  RCS state4=99, plus unknown fields inside and outside the record. Descriptor
  sources are `joxm/joxq`; timestamps stay in raw record bytes. Actual accepted
  live reads currently have zero records, so this record-bearing fixture is
  synthetic schema coverage, not evidence of a verified subscriber.

Decoder limits are 256 KiB per response, 64 result records/operation targets,
16 KiB per text/context value, and 8 KiB for the HTTPS carrier URL. Singular known
fields and conflicting known oneof payloads reject duplicates. Across Sync records,
duplicate verification/association detection compares exact bytes only; it cannot
normalize reordered protobuf fields or establish semantic identity of unknown data.
Unknown fields are retained in full original response/Verification/status/operation
bytes, rather than being reconstructed from the typed subset.

UPI provisioning fixtures use independently encoded synthetic inputs:

- `upi-provision-body.bin`: eligibility field1 explicitly 1, proof field2;
  proof version1, synthetic DG/salt, IMSI4, IMEI5, number credential7, cookie8,
  IID9 and logical session10. Optional MSISDN6 is absent. Sending uses standard
  padded Base64 of these exact bytes, with no line breaks.
- `upi-droidguard-inputs.json`: independent Python hashlib SHA-384 vectors for
  exact UTF-8 `value + salt`; the application name remains literal in version1.
- `upi-mls-signing-input.bin`: independently framed MLS label and synthetic UTF-8
  nonce. Tests sign this input with a fresh owned key and require the request
  validator to reject a signature when the context's nonce changes.
