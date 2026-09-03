use std::process::Command;

use archive_lint::{
    MAX_DECLARED_BYTES, MAX_ENTRY_BYTES, lint_archive_bytes, lint_archive_bytes_with_policy,
    render_json,
};

#[derive(Clone, Copy)]
struct Entry<'a> {
    name: &'a str,
    mode: u64,
    typeflag: u8,
    linkname: &'a str,
    size: u64,
    data: &'a [u8],
}

fn entry<'a>(
    name: &'a str,
    mode: u64,
    typeflag: u8,
    linkname: &'a str,
    data: &'a [u8],
) -> Entry<'a> {
    Entry {
        name,
        mode,
        typeflag,
        linkname,
        size: data.len() as u64,
        data,
    }
}

fn declared_entry<'a>(
    name: &'a str,
    mode: u64,
    typeflag: u8,
    linkname: &'a str,
    size: u64,
) -> Entry<'a> {
    Entry {
        name,
        mode,
        typeflag,
        linkname,
        size,
        data: &[],
    }
}

fn tar(entries: &[Entry<'_>]) -> Vec<u8> {
    let mut archive = Vec::new();
    for item in entries {
        let mut header = [0u8; 512];
        write_text(&mut header[0..100], item.name);
        write_octal(&mut header[100..108], item.mode);
        write_octal(&mut header[108..116], 1000);
        write_octal(&mut header[116..124], 1000);
        write_octal(&mut header[124..136], item.size);
        write_octal(&mut header[136..148], 0);
        header[148..156].fill(b' ');
        header[156] = item.typeflag;
        write_text(&mut header[157..257], item.linkname);
        write_text(&mut header[257..263], "ustar");
        write_text(&mut header[263..265], "00");
        write_text(&mut header[265..297], "root");
        write_text(&mut header[297..329], "root");
        write_octal(&mut header[329..337], 0);
        write_octal(&mut header[337..345], 0);
        write_text(&mut header[345..500], "");
        let checksum = header.iter().map(|byte| u64::from(*byte)).sum::<u64>();
        write_checksum(&mut header[148..156], checksum);
        archive.extend_from_slice(&header);
        archive.extend_from_slice(item.data);
        let padding = (512 - item.data.len() % 512) % 512;
        archive.resize(archive.len() + padding, 0);
    }
    archive.resize(archive.len() + 1024, 0);
    archive
}

fn write_text(field: &mut [u8], value: &str) {
    let bytes = value.as_bytes();
    assert!(bytes.len() <= field.len());
    field[..bytes.len()].copy_from_slice(bytes);
}

fn write_octal(field: &mut [u8], value: u64) {
    let width = field.len() - 1;
    let text = format!("{value:0width$o}");
    assert_eq!(text.len(), width);
    field[..width].copy_from_slice(text.as_bytes());
    field[width] = 0;
}

fn write_checksum(field: &mut [u8], value: u64) {
    let text = format!("{value:06o}");
    assert!(text.len() <= 6);
    field[..6].fill(b'0');
    field[6 - text.len()..6].copy_from_slice(text.as_bytes());
    field[6] = 0;
    field[7] = b' ';
}

fn finding_kinds(report: &archive_lint::Report) -> Vec<&str> {
    report
        .findings
        .iter()
        .map(|finding| finding.kind.as_str())
        .collect()
}

#[test]
fn valid_archive_fixture_is_safe() {
    let archive = tar(&[
        entry("README.txt", 0o644, b'0', "", b"valid"),
        entry("bin/", 0o755, b'5', "", b""),
    ]);
    let report = lint_archive_bytes("fixture.tar", &archive);
    assert!(report.parsed);
    assert_eq!(report.verdict, "safe");
    assert!(report.safe_to_extract);
    assert_eq!(report.entries, 2);
}

#[test]
fn rejects_parent_and_absolute_paths() {
    let archive = tar(&[
        entry("../outside", 0o644, b'0', "", b""),
        entry("/absolute", 0o644, b'0', "", b""),
    ]);
    let report = lint_archive_bytes("paths.tar", &archive);
    let kinds = finding_kinds(&report);
    assert!(kinds.contains(&"path-traversal"));
    assert!(kinds.contains(&"absolute-path"));
    assert_eq!(report.verdict, "unsafe");
}

#[test]
fn rejects_symlink_and_hardlink_escape() {
    let archive = tar(&[
        entry("link", 0o777, b'2', "../../outside", b""),
        entry("hard", 0o644, b'1', "../outside", b""),
    ]);
    let report = lint_archive_bytes("links.tar", &archive);
    let kinds = finding_kinds(&report);
    assert!(kinds.contains(&"symlink-outside-root"));
    assert!(kinds.contains(&"hardlink-outside-root"));
}

#[test]
fn detects_duplicate_paths() {
    let archive = tar(&[
        entry("same.txt", 0o644, b'0', "", b"a"),
        entry("same.txt", 0o644, b'0', "", b"b"),
    ]);
    let report = lint_archive_bytes("duplicate.tar", &archive);
    assert!(finding_kinds(&report).contains(&"duplicate-path"));
}

#[test]
fn detects_unicode_normalization_collision() {
    let archive = tar(&[
        entry("cafe\u{301}.txt", 0o644, b'0', "", b"a"),
        entry("caf\u{e9}.txt", 0o644, b'0', "", b"b"),
    ]);
    let report = lint_archive_bytes("unicode.tar", &archive);
    assert!(finding_kinds(&report).contains(&"path-normalization-collision"));
}

#[test]
fn detects_special_file_and_executable_permission() {
    let archive = tar(&[
        entry("device", 0o644, b'3', "", b""),
        entry("run.sh", 0o755, b'0', "", b""),
    ]);
    let report = lint_archive_bytes("metadata.tar", &archive);
    let kinds = finding_kinds(&report);
    assert!(kinds.contains(&"special-file"));
    assert!(kinds.contains(&"executable-permission"));
}

#[test]
fn enforces_oversized_entry_limit() {
    let archive = tar(&[declared_entry(
        "huge.bin",
        0o644,
        b'0',
        "",
        MAX_ENTRY_BYTES + 1,
    )]);
    let report = lint_archive_bytes("huge.tar", &archive);
    assert!(finding_kinds(&report).contains(&"oversized-entry"));
    assert_eq!(report.verdict, "unresolved");
}

#[test]
fn enforces_archive_bomb_limit() {
    let archive = tar(&[declared_entry(
        "expanded.bin",
        0o644,
        b'0',
        "",
        MAX_DECLARED_BYTES + 1,
    )]);
    let report = lint_archive_bytes("bomb.tar", &archive);
    assert!(finding_kinds(&report).contains(&"archive-bomb-limit"));
    assert_eq!(report.verdict, "unresolved");
}

#[test]
fn rejects_malformed_checksum_and_missing_end_marker() {
    let mut archive = tar(&[entry("bad", 0o644, b'0', "", b"")]);
    archive[0] ^= 1;
    archive.truncate(512);
    let report = lint_archive_bytes("malformed.tar", &archive);
    assert!(finding_kinds(&report).contains(&"malformed-header"));
    assert_eq!(report.verdict, "unresolved");
}

#[test]
fn reports_zip_as_unsupported_without_extracting() {
    let report = lint_archive_bytes("package.zip", b"PK\x03\x04not parsed");
    assert!(!report.parsed);
    assert_eq!(report.verdict, "unresolved");
    assert!(finding_kinds(&report).contains(&"unsupported-format"));
    assert!(!report.safe_to_extract);
}

#[test]
fn reports_unsupported_extended_metadata() {
    let archive = tar(&[entry("pax", 0o644, b'x', "", b"")]);
    let report = lint_archive_bytes("extended.tar", &archive);
    assert!(finding_kinds(&report).contains(&"unsupported-metadata"));
    assert_eq!(report.verdict, "unresolved");
}

#[test]
fn reports_unknown_tar_header_as_unresolved() {
    let mut archive = tar(&[entry("unknown", 0o644, b'0', "", b"")]);
    archive[257] = b'v';
    archive[148..156].fill(b' ');
    let checksum = archive[0..512]
        .iter()
        .map(|byte| u64::from(*byte))
        .sum::<u64>();
    write_checksum(&mut archive[148..156], checksum);
    let report = lint_archive_bytes("unknown.tar", &archive);
    assert!(finding_kinds(&report).contains(&"unsupported-tar-header"));
    assert_eq!(report.verdict, "unresolved");
}

#[test]
fn json_output_is_deterministic_and_policy_is_visible() {
    let archive = tar(&[entry("../outside", 0o644, b'0', "", b"")]);
    let first = lint_archive_bytes_with_policy("policy.tar", &archive, true);
    let second = lint_archive_bytes_with_policy("policy.tar", &archive, true);
    assert_eq!(render_json(&first).unwrap(), render_json(&second).unwrap());
    assert!(first.policy_check);
    assert!(
        render_json(&first)
            .unwrap()
            .contains("\"schema_version\": 1")
    );
}

#[test]
fn command_emits_json_and_nonzero_for_unsafe_archive() {
    let archive = tar(&[entry("../outside", 0o644, b'0', "", b"")]);
    let path = std::env::temp_dir().join(format!(
        "archive-lint-cli-{}-{}.tar",
        std::process::id(),
        std::thread::current().name().unwrap_or("test")
    ));
    std::fs::write(&path, archive).unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_archive-lint"))
        .arg(&path)
        .arg("--format")
        .arg("json")
        .output()
        .unwrap();
    std::fs::remove_file(&path).unwrap();
    assert_eq!(output.status.code(), Some(2));
    assert!(
        String::from_utf8(output.stdout)
            .unwrap()
            .contains("\"path-traversal\"")
    );
}
