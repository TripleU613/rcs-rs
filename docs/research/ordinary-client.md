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
operation; the installed build's active enforcement branch remains unverified.
An ordinary app cannot infer SIM-auth access from its identifier access.
Sources: [getIccAuthentication](https://developer.android.com/reference/android/telephony/TelephonyManager#getIccAuthentication(int,int,java.lang.String))
and [Android 17 permission definitions](https://android.googlesource.com/platform/frameworks/base/+/refs/heads/android17-release/core/res/AndroidManifest.xml).

An unrestricted cellular Internet request can use public `requestNetwork` and
`TelephonyNetworkSpecifier(subId)` with normal network permissions. Availability
still depends on device, subscription and data policy; this does not authorize a
restricted IMS network or guarantee secondary-SIM connectivity. Bind connections
and DNS to the returned network and release the callback.
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
carrier/ICC-auth privileges. No AKA operation or SIP registration was attempted
with this profile.

The profile contains repeated password-field names in different subtrees; they
must be kept by path. Values remain private. In [RCC.07 v3 Table 110](https://www.gsma.com/futurenetworks/wp-content/uploads/2019/09/RCC07_RCS5_1_advanced_communications_specification_v3.0.pdf),
the SIP `UserPwd` definition applies to Digest; this profile selects AKA. Its
separate XCAP authentication selects GBA. Nonempty fields do not establish an
alternate SIP authentication method. The repaired forensic copy was not used as
a runtime configuration.

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
No OTP completion, SIP registration or RCS messaging success has been observed
in these experiments, and they made no GPNV verification RPC.
