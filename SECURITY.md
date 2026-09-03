# Security policy

## Scope

archive-lint is a metadata-only tar auditor. It does not extract archives or claim safety for formats and metadata extensions it cannot parse. An unresolved report is a non-pass result.

## Supported versions

The latest 0.1.x release is supported.

## Reporting a vulnerability

Please use GitHub's private vulnerability reporting or open a private GitHub Security Advisory for this repository. Do not include an exploitable archive in a public issue.

Reports are most useful when they include the archive format, the smallest reproducing input, the observed report and exit code, and the archive-lint version. Do not send secrets or unrelated personal data.

## Security design

The parser uses bounded reads and lexical archive-root checks. It does not invoke tar, unzip, or another extractor; follow symlinks; create filesystem nodes; or inspect a destination filesystem. ZIP, pax extended metadata, GNU long-name metadata, compressed streams, and other unsupported formats remain unresolved.
