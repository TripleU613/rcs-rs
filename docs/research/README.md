# Research map

These records distinguish code behavior, local capability, provider acceptance
and actual RCS interoperability. Experiments are dated observations of a lab
environment; they are not a universal carrier or ROM compatibility promise.

## Current results

- Configuration discovery and RCS consent lookup have succeeded with externally
  supplied caller identity/proof inputs.
- A prior verification transaction received a real TS43 challenge, and lab
  carrier authentication produced a temporary token. The corrected follow-up
  still needs a complete successful live transaction.
- The latest completed verification Sync returned NONE / THROTTLED / status 8.
  Its roughly one-hour global retry instruction is not a quota reset guarantee.
  A different proxy route returned the same refusal.
- A fresh October 21 consent lookup still returned CONSENTED. The installed
  microG's Constellation action maps to a dummy service, so it is not a working
  reference verification client.
- Incoming-SMS codec and local token registration are separate from actual SMS
  delivery. A server-selected incoming-SMS challenge and successful completion
  by our client have not been demonstrated.
- No complete Google provisioning, registration or two-way RCS exchange exists.

## Read in this order

| Record | Purpose |
| --- | --- |
| [Provider access](provider-access.md) | Google verification/credential flow and carrier IMS distinctions |
| [Ordinary client](ordinary-client.md) | App permissions, live device checks and remaining platform gates |
| [Throttle investigation](verification-throttle-2026-10-20.md) | Captured retry semantics, original reports, proxy attempts and consent comparison |
| [Community routes](community-routes-2026-10-20.md) | microG lineage and firsthand interoperability reports |
| [GApps bootstrap](gapps-bootstrap.md) | Detailed recovered schemas, host operations and historical evidence |
| [Upstream reuse audit](upstream.md) | Pinned existing Rust RCS implementations and evaluation results |

For commands, see the [usage guide](../usage.md). For remaining milestones, see
the [interoperability plan](../superpowers/plans/2026-10-16-google-rcs-interoperability.md).

## Reproduction boundary

Public tests contain independently encoded synthetic fixtures. Google APIs can
require provider-approved application identity, genuine platform proofs and
real subscriber facts; those inputs are not bundled. Android research tools
document their own build requirements. Raw captures, reconstructed APK artifacts
and private phone coordinators are deliberately outside the public repository.

Public reports are leads until reproduced. A method working for Google Messages
with genuine Play services does not establish that it applies to microG or this
independent Rust client.
