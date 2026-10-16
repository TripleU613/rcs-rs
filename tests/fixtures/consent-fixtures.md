These fixtures contain synthetic values only, independently encoded from the recovered
GetConsent schema in original Google Play services 26.37.37 descriptors. They contain
no device captures, API keys, usable IID registrations, or DroidGuard results.

`consent-request.bin` uses `synthetic-iid`, checkin ID 123456, primary user serial 0,
locale en_US, version code 263737035 normalized to 263737, SDK 37, Generic/Example,
`synthetic-droidguard`, `org.example.sms`, and session UUID
00000000-0000-4000-8000-000000000000. The root DeviceId contains only the IID;
header ClientInfo DeviceId contains the IID plus checkin ID at fields 2 and 4.
Required extras are `required_consumer_consent=RCS` and
`consent_type=RCS_DEFAULT_ON_LEGAL_FYI_IN_SETTINGS`. No ClientAuth/SIM fields appear.

`consent-public-key.der` is SubjectPublicKeyInfo for the public P-256 standard generator
point. It exists solely as public test bytes; no private key is stored or generated.

`consent-response.bin` is the independently written byte sequence
`0a0410011801420208014206080210011805980607`:
outer field 1 has legacy state field **2**=1 and detail field 3=1;
outer repeated field 8 has client 1 with no state, then client 2/state 1/detail 5;
outer unknown field 99=7 proves byte preservation. Consent state does not establish
phone-number verification or RCS registration.
