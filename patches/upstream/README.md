# Pinned upstream evaluation patches

These patches repair the evaluated upstream code before genuine credentials are
loaded. They are not dependencies of the root `rcs-rs` crate yet. They add no
network or SIM operations and do not supply Android platform implementations.

| Checkout | Required commit | Patch |
| --- | --- | --- |
| `rust-rcs-core` | `f2f351c467ba6f2aa9a786647845b6ad21f300c5` | `0001-core-disable-protocol-logging.patch` |
| `rust-rcs-core` | same pin, after `0001` | `0003-core-digest-negotiation.patch` |
| `rust-rcs-client` | `720b42fad99d6d1f71dd89dcb11293245a0960d7` | `0002-client-trust-and-configuration.patch` |

The core patch makes the shared protocol logger silent in all build modes and
platforms. Callers include raw authentication, cookies, configuration and message
bodies. Its test captures a child process exercising real digest/header code and
checks synthetic plaintext and hex sentinels. Timing/worker diagnostic prints
outside that logger remain; they do not contain protocol credentials in the
inspected source.

The second core patch preserves the observed carrier `auth-init` token in the
Digest calculation and header, using the reference SIP client's auth-style A2
(method and URI, without the body hash). This is a compatibility behavior, not a
standard synonym for `auth-int` or proof that this carrier accepts our credentials.
Standard `auth`/`auth-int` choices take priority; list whitespace is trimmed.
Other unsupported or empty qop offers return `UnsupportedQop` instead of silently
falling back to a legacy response. Digest calculation errors now reach callers;
missing client nonces or unsupported hashes cannot produce a partial header.
Empty-body hashing reuses the case-insensitive hash constructor.

Eight synthetic tests cover RFC auth/no-qop vectors, the observed `auth-init`
calculation, uppercase MD5 with auth-int, list whitespace, unsupported qop and
error propagation. Six failed before the fixes while the two RFC controls passed.
`ErrorKind` gains `UnsupportedQop`; external exhaustive matches must handle it.
The reference source and separate rejected live query are recorded in the
[ordinary-client audit](../../docs/research/ordinary-client.md).

The client patch loads real PEM/DER roots recursively from `<root>/certs`, accepts
case-insensitive extensions and returns errors for missing/empty directories,
malformed certificates and traversal/read failures. It never logs certificates
or private keys. Rust `Context::new` now returns `io::Result<Context>`; the existing
C constructor returns null for root-loading failure. No certificate-validation
bypass or implicit system-root fallback is introduced.

The client pins its existing quick-xml dependency to 0.37.5, whose parser
[detects unclosed tag delimiters](https://github.com/tafia/quick-xml/blob/v0.37.5/src/reader/mod.rs#L307).
This retains its text/unescape APIs while replacing 0.31's permissive EOF handling.
The shared WAP reader rejects EOF/errors before closure, validates root attributes
and propagates nested characteristic/parameter errors. Its string parser requires
one top-level WAP document; the cache reader propagates incomplete WAP/cache
errors. This checks framing and exercised
fields, not full provisioning-schema validity or registration readiness. Rust
`read_wap_provisioning_doc` now returns `Result`, and `read_provisionging_doc`
returns `Option`; all in-tree callers are updated. External users passing a
quick-xml Reader must use the client's pinned version.

## Apply and test

From the `rcs-rs` checkout, choose an empty evaluation directory outside this repo:

```sh
RCS_PATCH_DIR="$PWD/patches/upstream"
RCS_EVAL_DIR="/tmp/rcs-upstream-evaluation"
mkdir "$RCS_EVAL_DIR"
git clone https://github.com/Hirohumi/rust-rcs-core "$RCS_EVAL_DIR/rust-rcs-core"
git clone https://github.com/Hirohumi/rust-rcs-client "$RCS_EVAL_DIR/rust-rcs-client"
git -C "$RCS_EVAL_DIR/rust-rcs-core" checkout --detach f2f351c467ba6f2aa9a786647845b6ad21f300c5
git -C "$RCS_EVAL_DIR/rust-rcs-client" checkout --detach 720b42fad99d6d1f71dd89dcb11293245a0960d7
git -C "$RCS_EVAL_DIR/rust-rcs-core" apply --check "$RCS_PATCH_DIR/0001-core-disable-protocol-logging.patch"
git -C "$RCS_EVAL_DIR/rust-rcs-core" apply "$RCS_PATCH_DIR/0001-core-disable-protocol-logging.patch"
git -C "$RCS_EVAL_DIR/rust-rcs-core" apply --check "$RCS_PATCH_DIR/0003-core-digest-negotiation.patch"
git -C "$RCS_EVAL_DIR/rust-rcs-core" apply "$RCS_PATCH_DIR/0003-core-digest-negotiation.patch"
git -C "$RCS_EVAL_DIR/rust-rcs-client" apply --check "$RCS_PATCH_DIR/0002-client-trust-and-configuration.patch"
git -C "$RCS_EVAL_DIR/rust-rcs-client" apply "$RCS_PATCH_DIR/0002-client-trust-and-configuration.patch"
cargo test --manifest-path "$RCS_EVAL_DIR/rust-rcs-core/Cargo.toml" --lib --tests
cargo test --manifest-path "$RCS_EVAL_DIR/rust-rcs-client/Cargo.toml"
```

Observed on Linux: core **14 functional tests**, client **14 tests**, and a separate
consumer **4 tests** pass. No configuration, DNS, HTTP, SIP or SIM request is
submitted by the new checks. Core's full default command also runs 11 doctests:
10 pass, while the existing `index_skipping_ows_and_obs_fold` example fails due
to a trailing newline in its fixture. The same failure was reproduced on the
unmodified pinned source; it is outside these patches. Upstream compiler warnings
remain. Neither upstream tracks Cargo.lock; source pins and patches are fixed,
but transitive dependency resolution is not pinned by this patch directory.

The certificate pair in the client patch is one synthetic self-signed test CA,
with only its public certificate included. Do not install it as a production
trust root. These patches and new tests use Apache-2.0; original copyright headers
are retained. See [the license](LICENSE-APACHE-2.0) and the
[reuse audit](../../docs/research/upstream.md). No live RCS interoperability or
Android linkage is established by these host tests.
