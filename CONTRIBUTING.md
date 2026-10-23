# Contributing

The immediate goal is an independently verifiable two-way RCS exchange with
Google Messages. This is a research prototype; successful decoding, local tests
and platform capability checks each establish only their own stage.

## Development checks

Use a current stable Rust toolchain. Before proposing a change, run:

```sh
cargo fmt --all -- --check
cargo test --locked --all-targets
cargo clippy --locked --all-targets -- -D warnings
```

Default checks are local and use synthetic data. Live examples require explicit
caller inputs and can initiate verification. Follow applicable provider waits;
a new process, identity or proxy is not evidence that a retry is allowed.

## Useful issues and pull requests

- State the concrete failure and expected behavior.
- Include the source revision, platform, sanitized status and stage reached.
- For a protocol change, identify the independent source for the field mapping
  and add a small synthetic fixture or transport check.
- For live results, distinguish server acceptance, number credentials,
  provisioning, registration and actual messaging. Record relevant timestamps
  and whether privileged phone operations were necessary.
- Keep fixes focused. Reuse the existing codecs, validation and redacted error
  patterns before adding another transport or abstraction.

## Data and attribution

Use invented fixture identifiers and public test domains. Never attach live
captures, private keys, API keys, account tokens, subscriber identifiers, phone
numbers, raw provisioning documents or session exports. Sanitize evidence before
opening an issue; the repository's ignore rules cannot protect issue attachments.

Keep upstream copyright notices and cite source revisions for adapted work.
Contributions are provided under the repository's Apache-2.0 license.
