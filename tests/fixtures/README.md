These are independently encoded, synthetic protobuf messages using the field
numbers documented in `docs/research/gapps-bootstrap.md`.

`request.bin` uses a fixed synthetic UUID, MCC/MNC `001`/`01`, device `generic`,
manufacturer `Example`, application `org.example.sms`, version `1`, Android ID
zero and no subscriber identifiers. It is a golden request fixture.

`request-with-gms.bin` uses that same independently encoded request plus the
installed-package entry `com.google.android.gms`, synthetic version `253000000`,
in Parameters repeated field6. It catches dropping the GMS context while
retaining the calling app's package/version. No installed version is invented
when the host does not supply one.

`request-with-gsf.bin` adds RequestContext field 2, the synthetic signed-int64
GServices ID `0x1020304050607080`, to that independently encoded GMS request.
The value exceeds JavaScript's exact integer range; no real device ID is used.

`onboarding.bin` has ACS host `rcs.example.test`, enabled state `1`, ignored
IMEI/IMSI formats (`4`), a 3600-second validity, and unknown fields in both the
onboarding flags and outer response. Other fixtures exercise disabled, missing,
duplicate and mismatched responses.

These files contain no live captures, Google application keys, real phone numbers
or subscriber identifiers. The localhost HTTP/2 test additionally sends an independently
defined future server field to exercise lossless response capture over gRPC.

`clientauth.xml` is a synthetic GSMA client-authenticity request containing only
`synthetic-*` challenge material. ACS tests also use loopback HTTP fixtures to
verify cookie retention, redirect rejection, backoff, and streamed body limits.
Only that loopback test fixture relaxes the production HTTPS requirement.

`direct-v2-inputs.json` contains nine SHA-384 binding values independently
calculated with Python `hashlib.sha384((value + salt).encode()).hexdigest()`;
DROIDGUARD_SALT hashes only the salt. Inputs are `org.example.sms`, session
`00000000-0000-4000-8000-000000000042`, synthetic IMSI `001010123456789`,
synthetic IMEI `123456789012345`, `synthetic-direct-cookie`,
`synthetic-carrier-token`, `synthetic-direct-challenge`, version text `2`, and
salt `00000000-0000-4000-8000-000000000043`.

`direct-v2-result.txt` is independently assembled with Python standard-library
Base64 and literal protobuf bytes: raw snapshot `fb ff ef` becomes unpadded
Base64URL `-__v`; the message is `08 02 12 04`, that four-byte string, `1a 24`
and the 36-byte salt above. Standard padded Base64 of those 46 bytes is the
fixture. This checks both alphabets, outer padding, exact salt and absence of
version-one fields. It is synthetic protocol data, not a VM proof or capture.
