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

`onboarding.bin` has ACS host `rcs.example.test`, enabled state `1`, ignored
IMEI/IMSI formats (`4`), a 3600-second validity, and unknown fields in both the
onboarding flags and outer response. Other fixtures exercise disabled, missing,
duplicate and mismatched responses.

These files contain no live captures, Google application keys, phone numbers or
SIM identifiers. The localhost HTTP/2 test additionally sends an independently
defined future server field to exercise lossless response capture over gRPC.

`clientauth.xml` is a synthetic GSMA client-authenticity request containing only
`synthetic-*` challenge material. ACS tests also use loopback HTTP fixtures to
verify cookie retention, redirect rejection, backoff, and streamed body limits.
Only that loopback test fixture relaxes the production HTTPS requirement.
