# archive-lint

Archive extraction safety auditor for Linux-first workflows.

archive-lint inspects tar headers and reports hazards before an extractor is allowed to run. It does not extract files, follow archive links, create filesystem nodes, or invoke tar, unzip, or another extractor.

## Status

MVP 0.1.0 is released. The parser supports small V7 and ustar-style tar headers. ZIP, pax extended metadata, GNU long-name metadata, compressed tar streams, and other archive formats are reported as unresolved rather than treated as safe.

## Commands

Audit a tar archive:

~~~text
archive-lint package.tar
archive-lint package.tar --format json
archive-lint policy-check package.tar
archive-lint package.zip --format json
~~~

Exit codes are stable for automation:

- 0 means the archive parsed completely and no finding was emitted.
- 2 means parsing completed but a policy finding was emitted.
- 3 means the result is unresolved because parsing or format support is incomplete.
- 1 means the input could not be read or the command could not run.

The strict policy-check command uses the same default limits and records policy_check: true in JSON output. It exists as an explicit gate for callers that want a named policy step.

## Findings

The MVP checks:

- relative member paths and .. traversal
- absolute member paths
- lexical symlink and hardlink escapes
- duplicate paths after separator and dot normalization
- Unicode NFC normalization collisions
- character devices, block devices, FIFOs, and contiguous special entries
- executable permission bits on regular files
- malformed checksums, octal fields, truncated payloads, and missing end markers
- per-entry, total declared payload, entry-count, and archive-byte limits
- unsupported ZIP and tar metadata formats

An archive is marked safe only when the full supported tar stream is parsed and no findings are present. A parsed archive with findings is unsafe. Unsupported or malformed input is unresolved, and safe_to_extract remains false.

## Limits

The default bounded parser accepts archives up to 64 MiB, 100,000 entries, 256 MiB per declared entry, and 128 MiB of total declared payload. These bounds constrain inspection and do not make an unsupported or malicious archive safe.

The path checks are lexical checks against an archive-root model. They do not inspect a destination filesystem, resolve host symlinks, or prove that every extractor implementation will behave identically. Use an isolated extractor with separate limits after this audit when extraction is required.

## Development

~~~bash
cargo fmt --all -- --check
cargo check --all-targets --locked
cargo clippy --all-targets --all-features --locked -- -D warnings
cargo test --all-targets --locked
RUSTDOCFLAGS=-Dwarnings cargo doc --no-deps --locked
cargo package --locked
cargo audit
git diff --check
~~~

The fuzz target exercises the parser without filesystem writes:

~~~bash
cargo +nightly fuzz run tar -- -max_total_time=10 -verbosity=0 -print_final_stats=1
~~~

## Research

The parser boundary, threat model, and evidence trail are recorded in docs/research.md. The release procedure is recorded in docs/release.md.

## License

MIT
