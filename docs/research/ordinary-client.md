# Ordinary Android client: requirements and evidence

The product target is a portable Rust RCS library usable by an ordinary open-source
SMS app: a normal APK on stock or custom Android, including installations without
GApps, root, Google Messages or privileged helpers. The rooted reference-client
experiments in the other research records do not establish this target.

## Platform boundary

The default SMS role grants the `read_device_identifiers` app-op. AOSP connects
that grant to subscriber/device identifier access, including IMSI and IMEI.
`READ_PHONE_STATE` alone does not grant these persistent identifiers to a modern
app. The unmodified capability probe held no SMS role and could not read IMSI or
IMEI. The separate app-op lab experiment below permitted IMSI access; actual
default-SMS-role enrollment remains untested.
Sources: [Android 17 SMS role](https://android.googlesource.com/platform/packages/modules/Permission/+/refs/heads/android17-release/PermissionController/res/xml/roles.xml),
[TelephonyPermissions](https://android.googlesource.com/platform/frameworks/base/+/refs/heads/android17-release/telephony/common/com/android/internal/telephony/TelephonyPermissions.java)
and [identifier app-op enforcement](https://android.googlesource.com/platform/frameworks/base/+/refs/heads/android17-release/services/core/java/com/android/server/pm/permission/LegacyPermissionManagerService.java).

SIM EAP-AKA has a separate gate. The SMS role does not grant
`USE_ICC_AUTH_WITH_DEVICE_IDENTIFIER` (`signature|appop`) or the newer
`USE_ICC_AUTH` (`signature|privileged`). Carrier privilege is another admission
path. Current API documentation retires `READ_PRIVILEGED_PHONE_STATE` for this
operation, but the installed build retains that fallback. The installed-code
audit below establishes its actual branch. An ordinary app cannot infer SIM-auth
access from its identifier access.
Sources: [getIccAuthentication](https://developer.android.com/reference/android/telephony/TelephonyManager#getIccAuthentication(int,int,java.lang.String))
and [Android 17 permission definitions](https://android.googlesource.com/platform/frameworks/base/+/refs/heads/android17-release/core/res/AndroidManifest.xml).

An unrestricted cellular Internet request can use public `requestNetwork` and
`TelephonyNetworkSpecifier(subId)` with normal network permissions. Availability
still depends on device, subscription and data policy; this does not authorize a
restricted IMS network or guarantee secondary-SIM connectivity. Bind connections
and DNS to the returned network and release the callback. The public
`TelephonyNetworkSpecifier.Builder` used by the private IMS probe requires API30;
the network-free public capability probe remains API29.
Sources: [ConnectivityManager](https://developer.android.com/reference/android/net/ConnectivityManager#requestNetwork(android.net.NetworkRequest,android.net.ConnectivityManager.NetworkCallback))
and [subscription selector](https://developer.android.com/reference/android/net/TelephonyNetworkSpecifier.Builder).

## Observed ordinary-client evidence — 2026-10-16

| Experiment | Observed result | What it establishes |
| --- | --- | --- |
| Normal APK, own signing identity, ordinary UID, SDK 37; default SMS app unchanged | Basic phone/network permissions granted; no carrier privilege, privileged phone permission or ICC-auth permission | The probe runs outside the rooted reference-client context. It was **not** the default SMS app. |
| Identifier reads from that APK | IMSI and IMEI threw `SecurityException`; own-number getter returned a value | This non-default caller could read its number but not these identifiers. No default-SMS identifier or SIM-auth success was tested. |
| MobileConfiguration with own package/certificate and a reference Google-project API key | `PermissionDenied`; no successful discovery | This caller/key combination failed. The initial CLI capture omitted the detailed reason; the diagnostic below resolves it. |
| Detailed diagnostic repeat of that discovery request with the same caller/key | `PermissionDenied`, with `google.rpc.ErrorInfo.reason = API_KEY_ANDROID_APP_BLOCKED`, independently decoded with `protoc` | The reference project's Android API-key restriction rejects this app identity ([Google's definition](https://docs.cloud.google.com/php/docs/reference/common-protos/latest/Api.ErrorReason)). An authorized own-project key was not tested; the result does not establish its availability or service access. |
| Initial anonymous ACS request | HTTP 400, with malformed vendor/version metadata and no subscriber identifier | An invalid/incomplete request; it cannot establish vendor rejection or admission policy. |
| ACS with own client vendor `RCRS`, formatted version `RCRS-0.1`, explicit owned number; no DroidGuard advertisement, IMSI, IMEI or Google API key | HTTP 400 | The corrected number-based request was not accepted; the response does not isolate the cause. |
| Explicit diagnostic capture of the same number-based caller | HTTP 400 with zero response-body bytes | Confirms the empty error response. This was a deliberate diagnostic request, not an automatic retry. |
| Controlled number-based comparison advertising DroidGuard, with the same own vendor/version and no proof submission | HTTP 400 | Advertising the method did not isolate the rejection. This lab comparison does not establish a working attestation implementation. |
| Same own number/client query from the ordinary APK over its selected default-data cellular network, with truthful `rcs-rs/0.1.0` User-Agent | HTTP 400, zero body bytes, no session-cookie header | The request reached ACS without root or a Google SDK/API key/attestation. Cellular routing did not produce an accepted session. Network path, HTTP stack and User-Agent changed, so this is not an IP-only comparison. |
| Standards-derived carrier ACS hostname | Resolves through the Linux host resolver and the selected cellular `Network` | Discovery without MobileConfiguration is possible for this test subscription. Resolution alone establishes no provisioning or authentication success. |
| Initial cellular HTTP GET to that carrier hostname's root, without query parameters | HTTP 511, empty body, session cookie | The standard PS bootstrap reaches an authentication stage. No number, identifier, API key or proof was sent in this cleartext request. |
| Same-origin cellular HTTPS with that cookie, own metadata and owned number | HTTP 400: `IMSI is missing in request params.` | This deployment requires IMSI for this request despite the generic baseline's number-only option. |
| Same HTTPS flow with the real SIM IMSI read by the app under a temporary identifier app-op lab grant | HTTP 200, 12,336-byte XML body; positive version/validity and two complete application subtrees, but missing the root end tag | A provisioning body was returned. It is not a validated, ready configuration. The real SMS-role grant and a GApps-free ROM were not tested. |

Private summaries: `runtime/ordinary-app-admission-20261016/` contains
`ordinary-app-summary.json`, `own-caller-discovery-summary.json`,
`acs-own-number/summary.json`, `acs-own-number-diagnostic/summary.json`,
`acs-own-number-dg-advertisement/summary.json`,
`acs-own-number-cellular-app/summary.json` and
`own-caller-discovery-diagnostic/classification-summary.json`. The standards route
is retained in `standard-acs-cellular-http/`, `standard-acs-cellular-https/` and
`standard-acs-cellular-imsi/`, including redacted structural summaries.
No number, identifier, API key, cookie, credential or proof belongs in this record.

The cellular experiment used a private instrumentation variant with the same own
package, version, signing key and normal UID. It requested public cellular Internet,
used network-bound DNS/connections, disabled redirects, bounded its response and
released its callback. It made one explicit request without an application retry.
The public capability probe remains network-free; the private variant was replaced
by that public APK after capture. Neither experiment established behavior on a
GApps-free ROM. The discovery key restriction does not explain the separate ACS
400 response, which used no Google API key.

## Installed platform audit and IMS transport — 2026-10-16

Wireless ADB pairing to the owned Pixel succeeded after USB system-file transfers
failed. Installed artifacts were transferred with valid ZIP/Dex contents. The
following hashes identify the code inspected; this is evidence about this
Android17/Lineage24 build, not a promise about every Android release or ROM.

| Installed artifact | SHA256 |
| --- | --- |
| `telephony-common.jar` | `4ad45c65d832311009721ff9d16cf2419395a09d91e05908b338f8ffda68d820` |
| `framework.jar` | `9655cce8302732c8033e236c9516e41bc5bea903763dc1e9382cb86244dc32a5` |
| `service-connectivity.jar` | `d9015de0c30bb033181a8f86adda6159946acaab54b2bb864fa752af8e359c7d` |
| `PermissionController.apk` | `05c00e77e6eb07ae77e402cf4e29b1df5293ce03773489b926c25151c1dd6a57` |

`PhoneSubInfoController.enforceIccSimChallengeResponsePermission` first tries
`TelephonyPermissions.checkCallingOrSelfUseIccAuthWithDeviceIdentifier`, then
`USE_ICC_AUTH` or selected-subscription carrier privilege, then
`READ_PRIVILEGED_PHONE_STATE` or selected-subscription carrier privilege. The
ICC-specific app-op accepts ALLOWED/FOREGROUND; DEFAULT requires the actual
`USE_ICC_AUTH_WITH_DEVICE_IDENTIFIER` permission. The distinct identifier app-op
is not checked. Enforcement runs before clearing the caller identity and before
the SIM operation. No authentication challenge was sent to establish these gates.

The installed ICC method has no `newSimAuthPermission` conditional. The relocated
flag getters return literal true, but that does not remove this build's visible
privileged-phone fallback. API documentation alone would have described this
installed implementation incorrectly.

The installed SMS role resource grants `read_device_identifiers`; it grants none
of those ICC permissions or the ICC-specific app-op. `SmsRoleBehavior.grantAsUser`
adds `PERFORM_IMS_SINGLE_REGISTRATION` and
`ACCESS_RCS_USER_CAPABILITY_EXCHANGE` only for system packages on AndroidS+.
Ordinary SMS-role enrollment was not performed; these are installed resource/code
findings, not observed post-enrollment grants. They provide no basis for assuming
that making an ordinary APK the default SMS app unlocks SIM AKA or SIP delegation.

`ConnectivityService.enforceNetworkRequestPermissions` rejects an active
restricted IMS request without the restricted-network authorization. Its carrier
exceptions cover CBS or eligible Wi-Fi requests, not this pure cellular IMS
request. Passive callbacks and `Network.bindSocket` have separate paths; the
active-request rejection cannot establish their outcome.

| Own ordinary-UID experiment | Observed result | Limit |
| --- | --- | --- |
| ICC preflight, selected default-data subscription | All three ICC-relevant permissions absent; no carrier privilege; ICC app-op DEFAULT; identifier app-op DENY | No installed ICC admission branch is satisfied. No SIM authentication was invoked. |
| Active cellular IMS `requestNetwork`, removing `NOT_RESTRICTED` | `SecurityException`, before callback registration | This caller cannot request that bearer. |
| Passive callback for the same subscription/IMS filter | Existing cellular IMS network observed; neither `INTERNET` nor `NOT_RESTRICTED` | Observation does not create a bearer or authorize authentication. |
| Unconnected UDP `Network.bindSocket` on that network | Returned successfully | Socket marking alone proves no packet delivery. Native enforcement details were not recovered. |
| One-shot OPTIONS diagnostic using the profile proxy, IMS-bound DNS | `UnknownHostException` before sending | No SIP send completed in this captured diagnostic. |
| Explicit default-network DNS comparison, socket still bound to IMS | DNS returned only IPv4; `LinkProperties.getLinkAddresses()` returned only IPv6 base-link addresses; send failed with `SocketException` / `ENETUNREACH` | No successful route was established. Stacked links, address translation and native routing/policy were not inspected; these family observations do not isolate the cause. No provider rejection or socket-permission conclusion follows. |

The OPTIONS diagnostic used forensic routing hints from the original complete
IMS application subtree, an owned-number guard and a truthful User-Agent. It
used the [default SIP UDP port 5060](https://www.rfc-editor.org/rfc/rfc3261.html#section-18.2.1),
at most one send call per explicit diagnostic, a bounded receive timeout,
no automatic retransmission and no Authorization, REGISTER, MESSAGE or AKA call.
It did not treat the incomplete document as a validated configuration. The final
captured send attempts did not complete; no SIP response was obtained. An earlier
prototype returned an incomplete instrumentation result without a send-state
record, so its send outcome is unknown.

Private inputs and captures remain outside Git under
`runtime/platform-auth-audit-20261016/`: `ims-network-summary.json`,
`ims-sip-ims-dns-summary.json`, `ims-sip-summary.json`, and the focused reports in
`static/carrier-static/`, `static/roles/` and `static/rcs_runtime/`. After the
diagnostics, the original nondebug capability APK's exact hash was restored,
private input was removed, callbacks were released, and the SMS holder and
identifier app-op mode were unchanged. Wireless debugging/pairing remains enabled
for ongoing research. These observations are from the rooted custom-ROM/microG
test phone using an ordinary app UID; clean vanilla behavior remains untested.

### Advertised IPv6 proxy and authentication follow-up

The same IMS connection advertised three IPv6 P-CSCF addresses. A read-only
system capture supplied one to the private APK; a fresh capture and network-ID
guard checked it before use. This supplied address is a laboratory input:
`LinkProperties.getPcscfServers` is a system API absent from the public SDK36.
The public telephony P-CSCF getter is also unavailable there; the installed
privileged implementation reads ISIM contents, rather than the current bearer PCO.
Public base-link/DNS/route/NAT64 getters do not expose all stacked links.

[RCC.07 v3 A.1.6.1](https://www.gsma.com/futurenetworks/wp-content/uploads/2019/09/RCC07_RCS5_1_advanced_communications_specification_v3.0.pdf)
describes shared VoLTE IMS using its default settings and the proxy discovered
through PCO; A.1.6.2 separately describes configured LBO proxy discovery.
That distinction motivated the advertised-proxy diagnostic. It does not establish
this deployment's exact RCS registrar selection or permission to add a binding.

| Later ordinary-UID diagnostic | Observed result | What remains open |
| --- | --- | --- |
| One OPTIONS to the advertised IPv6 proxy, socket bound to the observed IMS network | Matching Call-ID/CSeq, SIP 403, 485-byte response, no authentication challenge | Demonstrates a SIP round trip; no registration or subscriber admission. |
| Read the owned UDP socket's SO_MARK through a small JNI helper | Nonzero low-16-bit network ID matches IMS after binding | Confirms actual selection in this build. It does not establish universal Android authorization policy. |
| REGISTER query with no Contact, Expires or Authorization | Matching 401, Digest MD5, literal `qop="auth-init"`, opaque present, realm matches profile | A real challenge, not accepted credentials or an AKA response. |
| One authenticated contact-free query using the profile's APPAUTH username/password and a Rust-generated `auth-init` response | Matching 403 with Reason cause403, Warning399 and a `user_unknown` indication | This supplied context was rejected. Later source inspection showed that the reference parser skips these credential fields for this AKA profile; this is not a test of its proper AKA route. |

A REGISTER without Contact fetches bindings and leaves them unchanged under
[RFC3261 §10.2.3](https://www.rfc-editor.org/rfc/rfc3261.html#section-10.2.3).
The authenticated query reused the challenge's Call-ID and From tag, increased
CSeq to2, used a fresh client nonce and preserved the server nonce/opaque/qop.
There was one explicit credential-bearing send, no retry, guessed password,
binding request or SIM authentication call. The challenge was about 11 minutes
old and the query used a new UDP socket. A later control fetched a fresh challenge
and answered immediately on the same connected socket, with the same Call-ID,
From tag and local address/port, increasing CSeq from1 to2. It again returned
403 with a `user_unknown` indication, without a new challenge or explicit stale
indication. An independent Python calculation and the patched Rust engine both
matched that control's exact wire proof. These checks remove the challenge-age
and changed-socket differences; they still do not establish which identity,
registrar or enrollment requirement caused rejection.

A subsequent parser audit changes the interpretation of both proofs. In this
exact reference, `ejsw.a` copies APPAUTH realm/username/password only when AuthType
is `Digest`. This profile says `AKA`, so the reference leaves those Digest fields
empty. Its separate private IMS identity differs from APPAUTH UserName. The
internal REGISTER builder has no AKA branch or private-identity substitution;
if invoked with those defaults, it emits an empty-username/realm MD5 offer.
Whether a separate native/provider path handles AKA remains unresolved. Thus
the static-password experiments were off-reference for this profile. They do
not show rejection of the correct AKA identity or SIM response.

A separate query then offered `AKAv1-MD5` with the exact profile
Private_User_Identity, home domain and empty nonce/response. This was an
independent candidate-engine diagnostic, not a recovered Google AKA flow: the
candidate Rust engine selects that identity for AKA, and its existing serializer
generated the offer. It sent one contact-free request and received matching
SIP500, Reason cause500 and Warning399, without WWW-Authenticate. No SIM operation
or authentication response followed. The query does not establish that these
profile fields, proxy or omitted registration/security context form an accepted
AKA route.

The `auth-init` calculation is source-backed reference behavior: Messages APK
version324451063, SHA256
`2f666c55f129da84e1606d06e183ee08faf2b560d5a53cb44835007b4a97b159`.
`ejlx.b` stores the challenge parameters; `ejpa.m` constructs REGISTER and calls
`ekmf.b`. The helper accepts qop strings starting with `auth`, includes the
original token with nc/cnonce in the response, and adds a body hash only for exact
`auth-int`. The REGISTER path emits the original qop value. This is not a public
specification for arbitrary `auth*` tokens or current-version interoperability.
The [Digest evaluation patch](../../patches/upstream/README.md) supports only the
observed additional token and rejects other unsupported offers. Its synthetic
vectors and an independent calculation agree; actual carrier admission did not.

Private evidence: `ims-pco-summary.json`, `ims-mark-summary.json`,
`ims-register-query-summary.json`, `ims-register-query-auth-summary.json`,
`ims-register-auth-query-summary.json` and
`ims-register-auth-query-error-classification.json`, plus
`ims-register-fresh-query-summary.json` and
`ims-register-fresh-query-verification-summary.json`, plus
`ims-register-aka-initial-summary.json` and
`ims-register-aka-initial-verification-summary.json`; source reports in
`static/rcs_runtime/auth-init/`, `static/rcs_runtime/pcscf-public-api-findings.md`
and `static/rcs_runtime/config-identity-followup.md`, plus
`static/native-routing/`. The native client can return success if connecting
to its fwmark daemon fails; therefore successful Java binding alone was weaker
evidence than the later socket-mark read-back. Exact daemon policy is unaudited.
All completed runs restored the original APK, removed private inputs and retained
the SMS holder/identifier app-op mode. Wireless debugging remains enabled.

Public `DnsResolver.rawQuery` for NAPTR on the configured proxy name and SRV on
its `_sip._udp` name both timed out over IMS, with a 3.5-second limit and
cancellation for each. A separate direct UDP comparison selected the first DNS
server from public `LinkProperties.getDnsServers`, verified the socket mark and
sent one query per type; both timed out after2.5 seconds. This does not distinguish
network filtering, unavailable DNS or resolver policy, and supplied no replacement
endpoint. No SIP or credential-bearing request was sent in these DNS checks.
The same names queried through the default Internet network did return DNS
responses: the NAPTR query contained a CNAME and no NAPTR answer; the SRV name
returned NXDOMAIN. This is a bounded comparison, not complete SIP discovery.
Captures: `ims-dns-summary.json`, `ims-dns-udp-summary.json` and
`default-dns-summary.json`.

## Standards route and remaining capabilities

[RCC.14 v10 §§2.2.1 and 2.5.2](https://www.gsma.com/newsroom/wp-content/uploads/RCC.14-v10.0-1.pdf)
specifies the default carrier hostname
`config.rcs.mnc<MNC>.mcc<MCC>.pub.3gppnetwork.org`, with two-digit MNCs padded to
three digits. Its initial cellular HTTP request has no provisioning query;
HTTP 511 selects further authentication, retaining any returned cookie for HTTPS.
These rules motivated the separate standards-route experiment above.

That HTTPS variant used the same owned APK identity and a temporary
`READ_DEVICE_IDENTIFIERS` app-op grant, corresponding to the identifier app-op
documented for the SMS role. The existing SMS role stayed unchanged. The script
restored the observed prior `deny` mode in `finally` and removed its private cookie
file. A debuggable lab build allowed the captured same-origin cookie to be placed
in app-private storage via `adb run-as`; the app adopted no shell identity.
This setup does not demonstrate a production SMS-role enrollment flow.

Strict XML parsing rejects the returned body at EOF. Forensic parsing with only
the missing root end tag supplied finds chat/group-chat/file-transfer enabled,
`AuthType=AKA`, the IMS APN, and single registration. Standalone messaging is
disabled. The profile therefore calls for SIM authentication and an IMS route;
ordinary Internet connectivity does not establish those capabilities. The test
phone did not advertise single-registration support, and the probe has no
carrier/ICC-auth privileges. No AKA operation or registration binding was
requested with this profile; later contact-free REGISTER diagnostics are
described above.

The profile contains repeated password-field names in different subtrees; they
must be kept by path. Values remain private. In [RCC.07 v3 Table 110](https://www.gsma.com/futurenetworks/wp-content/uploads/2019/09/RCC07_RCS5_1_advanced_communications_specification_v3.0.pdf),
the SIP `UserPwd` definition applies to Digest; this profile selects AKA. Its
separate XCAP authentication selects GBA. Nonempty fields do not establish an
alternate SIP authentication method. The repaired forensic copy was not used as
a runtime configuration. The later OPTIONS diagnostics used only the original
closed application subtree's routing fields and did not authenticate or register.

## Request syntax and authenticity

[RCC.07 RCS 5.1 v3.0](https://www.gsma.com/futurenetworks/wp-content/uploads/2019/09/RCC07_RCS5_1_advanced_communications_specification_v3.0.pdf),
Tables 4/12, permits four-character vendor fields and requires client version
`Platform-Major.Minor`: platform at most nine alphanumeric characters, each
numeric component at most two, total at most fifteen. `RCRS-0.1` fits; a bare
`0.1.0` does not. Terminal model/software limits are ten characters. `5.1B` is the
specified RCS version; profile meanings are externally defined. The non-PS
primary-device procedure requires MSISDN when IMSI is absent. Syntax alone does
not establish provider acceptance.

`client_authenticity_support` is standardized by later GSMA specifications;
`goog-droidguard` is a Google-specific method value. It is absent from the
examined 5.1B baseline. [RCC.14 v10 §2.11](https://www.gsma.com/newsroom/wp-content/uploads/RCC.14-v10.0-1.pdf)
requires authenticity support in its prose, despite marking the parameter optional
in Table 17. Deployments mandating it specify HTTP 426 for a missing advertisement.
Omitting unsupported capabilities is not a guarantee of current-spec compliance
or service admission. Do not advertise a method the host cannot perform.

No Google-specific HTTP User-Agent is required by the examined baseline.
An honest product/version User-Agent follows [RFC 9110 §10.1.5](https://www.rfc-editor.org/rfc/rfc9110.html#name-user-agent).
RCC.14's GBA product-token requirement applies specifically to GBA-capable clients.

## Library boundary and next proof

`AcsSession::initial_challenge` accepts explicit `Option<ClientAuthenticity>`;
`None` avoids advertising a Google attestation implementation the host lacks.
`msisdn_challenge` accepts an owned number and the same capability choice, but
only begins provisioning. OTP handling is not implemented; the UPI path is
unchanged. These APIs do not establish accepted configuration or registration.

API 29 is the current capability probe's floor, not a global product minimum.
Next evidence must come from the ordinary app's actual UID and declared
capabilities, including a separately tested default-SMS role where appropriate.
This carrier profile still needs a usable IMS route and an authorized SIM-auth
path; neither is supplied by the current probe. The unresolved routing failure
must not be papered over with a guessed proxy or a root-only shipping dependency.
No OTP completion, SIP registration or RCS messaging success has been observed
in these experiments, and they made no GPNV verification RPC.
