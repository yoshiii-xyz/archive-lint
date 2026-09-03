# Research notes

## Decision

The 0.1.0 MVP audits uncompressed V7 and ustar-style tar headers in memory. It never extracts input and never delegates parsing to an extractor. ZIP is detected and reported as unsupported. POSIX pax extended metadata and GNU long-name metadata are also unresolved in this release.

The decision keeps the proof obligation narrow. GNU tar documents that a tar archive is a sequence of 512-byte headers and payloads terminated by two zero blocks, and that headers carry names, checksums, sizes, and file types. GNU tar also documents symlink and hardlink members and warns that archive formats have meaningful compatibility differences. The Open Group index identifies ustar interchange format and pax extended headers as distinct parts of the archive specification. The implementation therefore validates the bounded tar stream and reports every format boundary instead of inferring safety from a partial parse.

Rust's std::path documentation says component iteration performs only basic lexical normalization and does not resolve .. or symlinks. The implementation uses an archive-root lexical model for member names and link targets. It does not call canonicalize, because there is no trusted destination filesystem involved in pre-extraction inspection.

## Threat model and limits

The input may be attacker-controlled and may be malformed. The parser bounds the input byte count, entry count, per-entry declared bytes, and total declared payload. It validates checksums and octal fields before using offsets. It never creates files, follows links, invokes an extractor, or writes an extraction directory.

The audit covers:

- .. components and absolute member names
- symlink and hardlink targets that lexically escape the archive root
- duplicate paths after separator and dot normalization
- Unicode NFC collisions
- special filesystem node typeflags
- executable permission bits on regular files
- malformed headers, truncated payloads, missing end markers, and declared-size limits

The audit does not prove safety for unsupported formats, compressed streams, pax/GNU metadata extensions, host filesystem races, extractor-specific behavior, or symlink chains that require modeling a complete destination filesystem. An unresolved report is deliberately not a pass.

## Sources

- [GNU tar manual, basic tar format](https://www.gnu.org/software/tar/manual/tar.html#Basic-Tar-Format)
- [GNU tar manual, archive formats and ustar limits](https://www.gnu.org/software/tar/manual/tar.html#Formats)
- [GNU tar manual, symbolic links](https://www.gnu.org/software/tar/manual/tar.html#Symbolic-Links)
- [GNU tar manual, hard links](https://www.gnu.org/software/tar/manual/tar.html#Hard-Links)
- [The Open Group POSIX utility contents, including pax and ustar interchange format](https://pubs.opengroup.org/onlinepubs/9699919799/utilities/contents.html)
- [Rust standard library path module](https://doc.rust-lang.org/std/path/)
- [Rust standard library Component enum](https://doc.rust-lang.org/std/path/enum.Component.html)

## Verification plan

The required cases are implemented as integration tests in tests/archive_lint.rs. The test fixture builder writes tar headers directly and does not invoke an extractor. A bounded nightly fuzz run exercises arbitrary byte strings through the same read-only parser.
