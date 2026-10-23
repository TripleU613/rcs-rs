# rcs-rs

**An experimental Rust foundation for independent RCS clients.**

[![CI](https://github.com/TripleU613/rcs-rs/actions/workflows/ci.yml/badge.svg)](https://github.com/TripleU613/rcs-rs/actions/workflows/ci.yml)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

The goal is to let an open source SMS app add RCS through a reusable Rust
library while retaining its own conversations and SMS transport. The intended
Android host is a normal APK on stock or custom ROMs, including builds without
GApps. Google Messages, microG and root are research tools in the current lab.

> **Research prototype. No successful Google RCS registration or two-way
> messaging has been demonstrated.** The present crate implements discovery,
> provisioning and number-verification building blocks, not a complete RCS engine.

## What works today

| Area | Implemented and checked | Live result and limit |
| --- | --- | --- |
| Configuration discovery | Bounded protobuf decoding, real installed-GMS context, redacted diagnostics | Rust reached configuration discovery with reference caller inputs; independent client admission remains open |
| ACS provisioning | Stateful cookies, direct TS43 and UPI challenge/proof framing, owned MLS proof validation | Challenges and carrier temporary tokens observed in the lab; no accepted complete Google provisioning flow |
| Number verification | Consent lookup, Sync/Proceed, TS43 and incoming-SMS codecs | Consent succeeds; latest completed Sync returned `THROTTLED` / status 8 |
| Existing-number lookup | Signed read-only requests and bounded record decoding | Live request succeeded with zero number records |
| Android integration | Ordinary-app permission probe, owned check-in/MLS identity tools, VM-material boundaries | Several host capabilities checked; privileged lab operations do not establish ordinary-app availability |
| Proxy experiment | Explicit HTTP CONNECT for PDV Sync/Proceed with origin TLS and no direct fallback | Replacement proxy reached Google; the same verification throttle remained |
| Registration and messaging | Research and implementation plan | No registration binding, verified RCS message exchange or production Android SDK |

The success criterion is a text sent by this library to current Google Messages
and a reply received over verified RCS, independently of Google Messages on the
sending device. Each earlier step is an intermediate result.

## Start locally

Install a current stable Rust toolchain with Cargo, rustfmt and Clippy.

```sh
git clone https://github.com/TripleU613/rcs-rs.git
cd rcs-rs
cargo test --locked --all-targets
cargo fmt --all -- --check
cargo clippy --locked --all-targets -- -D warnings
```

Default tests use synthetic fixtures and local HTTP/gRPC servers. They need no
SIM, phone, Google account, API key or live provider access. The ignored live
proxy check is explicitly opt-in. The Android research tools have separate
SDK/device prerequisites in their own READMEs.

The crate is not published to crates.io. For local evaluation:

```toml
[dependencies]
rcs-rs = { path = "../rcs-rs" }
```

## Explore the project

| Start here | Contents |
| --- | --- |
| [Usage guide](docs/usage.md) | Example commands, private input requirements, Sync/Proceed, incoming-SMS metadata and ACS APIs |
| [Research index](docs/research/README.md) | Evidence map, current blockers and dated experiments |
| [Ordinary Android client](docs/research/ordinary-client.md) | Permission gates, independent APK checks and vanilla-ROM limits |
| [Provider access](docs/research/provider-access.md) | Google credential/provisioning flow and carrier IMS comparison |
| [Verification throttle](docs/research/verification-throttle-2026-10-20.md) | Two distinct retry fields, public recovery reports and actual proxy outcomes |
| [Community research](docs/research/community-routes-2026-10-20.md) | microG implementation lineage and reported successes, with original sources |
| [Wire and platform research](docs/research/gapps-bootstrap.md) | Recovered behavior, artifact references and per-experiment limitations |
| [Interoperability plan](docs/superpowers/plans/2026-10-16-google-rcs-interoperability.md) | Remaining work through a two-way RCS exchange |

### Source layout

```text
src/                 Discovery, consent, ACS and verification library
examples/            Explicit discovery, challenge, consent and verification probes
tests/fixtures/      Independently encoded synthetic protocol fixtures
tools/               Android admission, owned identity and VM-material research tools
patches/upstream/    Pinned evaluation patches for existing Rust RCS projects
docs/                Usage, evidence, design and interoperability plan
```

The shipping boundary is the Rust library plus an application-owned Android
host. Live carrier authentication and platform proofs still require host work;
private laboratory coordinators are not a distributed SDK.

## Current investigation

The retained Google Sync responses contain a roughly one-hour **global retry
instruction**, while the individual verification record's retry value is zero.
Waiting beyond one hour and changing the network route both still produced the
same refusal. The quota key and reset window remain unknown. A fresh October 21
consent lookup still reported RCS consent granted.

Incoming-SMS verification is the next distinct experiment: the library can
encode a matched server-selected challenge, and the CLI can accept metadata from
a real active Android receiver. Actual delivery, a server SMS challenge and a
successful Proceed remain unproven. See the [dated investigation](docs/research/verification-throttle-2026-10-20.md).

## Contribute

Useful contributions reproduce a specific failure, validate a wire field against
an independent source, exercise an ordinary Android capability, or demonstrate a
complete provider-admitted flow. Include what actually ran and what remains
unproven. See [CONTRIBUTING.md](CONTRIBUTING.md).

Keep real phone numbers, SIM/device identifiers, tokens, signing keys, account
data, provisioning credentials, APKs and raw captures outside Git and issues.
Fixtures must be synthetic. See [fixture provenance](tests/fixtures/README.md).

## Related work and license

This project evaluates [rust-rcs-client](https://github.com/Hirohumi/rust-rcs-client)
and [rust-rcs-core](https://github.com/Hirohumi/rust-rcs-core) before duplicating a
SIP/MSRP stack; [pinned patches and their limits](patches/upstream/README.md) are
included. [microG's Constellation work](https://github.com/microg/GmsCore/pull/3359)
is an important reference for Google number verification. Their results do not
establish interoperability for this independent client.

Licensed under [Apache-2.0](LICENSE). Retained upstream attribution and research
tool provenance are described in [NOTICE](NOTICE) and the relevant tool READMEs.
This is an independent project, unaffiliated with Google or the GSMA.
