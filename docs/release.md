# Release checklist

Release archive-lint only after all of the following are observed in the current checkout:

- cargo fmt --all -- --check
- cargo check --all-targets --locked
- cargo clippy --all-targets --all-features --locked -- -D warnings
- cargo test --all-targets --locked
- RUSTDOCFLAGS=-Dwarnings cargo doc --no-deps --locked
- cargo package --locked
- cargo audit
- git diff --check
- bounded nightly fuzz run with a hard timeout
- clean cargo install from the packaged crate in a fresh temporary directory
- CLI smoke tests for safe, unsafe, unresolved tar, and unsupported ZIP inputs
- successful GitHub Actions CI, Security, CodeQL, and tag package checks
- repository branch protection and secret scanning settings verified
- a GitHub release and crates.io publication whose hashes and URLs are recorded in private QA evidence

The parser's unresolved verdict must remain nonzero in automation. Do not describe support for ZIP, pax, GNU long names, compression, or dynamic extraction until a separate bounded implementation and tests exist.
