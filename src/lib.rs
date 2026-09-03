use std::{collections::BTreeMap, fs, io, path::Path};

use serde::Serialize;
use unicode_normalization::UnicodeNormalization;

pub const MAX_ARCHIVE_BYTES: u64 = 64 * 1024 * 1024;
pub const MAX_ENTRIES: usize = 100_000;
pub const MAX_ENTRY_BYTES: u64 = 256 * 1024 * 1024;
pub const MAX_DECLARED_BYTES: u64 = 128 * 1024 * 1024;

const BLOCK_SIZE: usize = 512;

#[derive(Clone, Debug, Serialize)]
pub struct Limits {
    pub max_archive_bytes: u64,
    pub max_entries: usize,
    pub max_entry_bytes: u64,
    pub max_declared_bytes: u64,
}

#[derive(Clone, Debug, Serialize)]
pub struct Finding {
    pub kind: String,
    pub severity: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    pub detail: String,
}

#[derive(Clone, Debug, Serialize)]
pub struct Report {
    pub schema_version: u8,
    pub tool: String,
    pub input: String,
    pub format: String,
    pub policy_check: bool,
    pub parsed: bool,
    pub verdict: String,
    pub safe_to_extract: bool,
    pub entries: usize,
    pub declared_bytes: u64,
    pub bytes_scanned: u64,
    pub archive_bytes: u64,
    pub limits: Limits,
    pub findings: Vec<Finding>,
}

impl Report {
    pub fn exit_code(&self) -> i32 {
        match self.verdict.as_str() {
            "safe" => 0,
            "unsafe" => 2,
            _ => 3,
        }
    }
}

pub fn lint_archive(path: &Path, policy_check: bool) -> io::Result<Report> {
    let input = path.display().to_string();
    let archive_bytes = fs::metadata(path)?.len();

    if archive_bytes > MAX_ARCHIVE_BYTES {
        let mut report = new_report(
            input,
            detect_format(path.to_string_lossy().as_ref(), &[]).to_string(),
            policy_check,
            archive_bytes,
        );
        report.parsed = false;
        add_finding(
            &mut report,
            "archive-size-limit",
            "error",
            None,
            format!(
                "archive is {archive_bytes} bytes, above the {} byte input limit",
                MAX_ARCHIVE_BYTES
            ),
        );
        finalize(&mut report);
        return Ok(report);
    }

    let bytes = fs::read(path)?;
    Ok(lint_archive_bytes_with_policy(&input, &bytes, policy_check))
}

pub fn lint_archive_bytes(input: &str, bytes: &[u8]) -> Report {
    lint_archive_bytes_with_policy(input, bytes, false)
}

pub fn lint_archive_bytes_with_policy(input: &str, bytes: &[u8], policy_check: bool) -> Report {
    let format = detect_format(input, bytes);
    let mut report = new_report(
        input.to_owned(),
        format.to_owned(),
        policy_check,
        u64::try_from(bytes.len()).unwrap_or(u64::MAX),
    );

    if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > MAX_ARCHIVE_BYTES {
        report.parsed = false;
        add_finding(
            &mut report,
            "archive-size-limit",
            "error",
            None,
            format!("archive exceeds the {} byte input limit", MAX_ARCHIVE_BYTES),
        );
        finalize(&mut report);
        return report;
    }

    if format == "zip" {
        report.parsed = false;
        add_finding(
            &mut report,
            "unsupported-format",
            "error",
            None,
            "ZIP input is detected but ZIP parsing is not part of this MVP",
        );
        finalize(&mut report);
        return report;
    }

    TarParser::new(bytes, report).parse()
}

pub fn render_json(report: &Report) -> serde_json::Result<String> {
    serde_json::to_string_pretty(report)
}

pub fn render_text(report: &Report) -> String {
    let mut output = String::new();
    output.push_str("archive-lint schema=1\n");
    output.push_str(&format!("input: {}\n", report.input));
    output.push_str(&format!("format: {}\n", report.format));
    output.push_str(&format!("policy_check: {}\n", report.policy_check));
    output.push_str(&format!("parsed: {}\n", report.parsed));
    output.push_str(&format!("verdict: {}\n", report.verdict));
    output.push_str(&format!("safe_to_extract: {}\n", report.safe_to_extract));
    output.push_str(&format!("entries: {}\n", report.entries));
    output.push_str(&format!("declared_bytes: {}\n", report.declared_bytes));
    output.push_str(&format!("bytes_scanned: {}\n", report.bytes_scanned));
    output.push_str(&format!("archive_bytes: {}\n", report.archive_bytes));
    output.push_str(&format!(
        "limits: archive_bytes={} entries={} entry_bytes={} declared_bytes={}\n",
        report.limits.max_archive_bytes,
        report.limits.max_entries,
        report.limits.max_entry_bytes,
        report.limits.max_declared_bytes
    ));

    if report.findings.is_empty() {
        output.push_str("findings: none\n");
    } else {
        output.push_str("findings:\n");
        for finding in &report.findings {
            let path = finding
                .path
                .as_deref()
                .map(|value| format!(" path={value}"))
                .unwrap_or_default();
            output.push_str(&format!(
                "- {} severity={}{} detail={}\n",
                finding.kind, finding.severity, path, finding.detail
            ));
        }
    }
    output
}

fn new_report(input: String, format: String, policy_check: bool, archive_bytes: u64) -> Report {
    Report {
        schema_version: 1,
        tool: "archive-lint".to_owned(),
        input,
        format,
        policy_check,
        parsed: true,
        verdict: "unresolved".to_owned(),
        safe_to_extract: false,
        entries: 0,
        declared_bytes: 0,
        bytes_scanned: 0,
        archive_bytes,
        limits: Limits {
            max_archive_bytes: MAX_ARCHIVE_BYTES,
            max_entries: MAX_ENTRIES,
            max_entry_bytes: MAX_ENTRY_BYTES,
            max_declared_bytes: MAX_DECLARED_BYTES,
        },
        findings: Vec::new(),
    }
}

fn detect_format(input: &str, bytes: &[u8]) -> &'static str {
    let extension_is_zip = Path::new(input)
        .extension()
        .and_then(|extension| extension.to_str())
        .map(|extension| extension.eq_ignore_ascii_case("zip"))
        .unwrap_or(false);
    let signature_is_zip = bytes.starts_with(b"PK\x03\x04")
        || bytes.starts_with(b"PK\x05\x06")
        || bytes.starts_with(b"PK\x07\x08");
    if extension_is_zip || signature_is_zip {
        "zip"
    } else {
        "tar"
    }
}

struct TarParser<'a> {
    bytes: &'a [u8],
    report: Report,
    seen: BTreeMap<String, String>,
    hardlinks: Vec<(String, String)>,
}

impl<'a> TarParser<'a> {
    fn new(bytes: &'a [u8], report: Report) -> Self {
        Self {
            bytes,
            report,
            seen: BTreeMap::new(),
            hardlinks: Vec::new(),
        }
    }

    fn parse(mut self) -> Report {
        let mut offset = 0usize;
        let mut zero_blocks = 0usize;
        let mut terminated = false;

        while offset + BLOCK_SIZE <= self.bytes.len() {
            let header = &self.bytes[offset..offset + BLOCK_SIZE];
            if header.iter().all(|byte| *byte == 0) {
                zero_blocks += 1;
                offset += BLOCK_SIZE;
                self.report.bytes_scanned = offset as u64;
                if zero_blocks == 2 {
                    terminated = true;
                    break;
                }
                continue;
            }

            if zero_blocks > 0 {
                self.report.parsed = false;
                add_finding(
                    &mut self.report,
                    "malformed-end-marker",
                    "error",
                    None,
                    "a zero block was not followed by the required second zero block",
                );
                break;
            }
            zero_blocks = 0;

            if self.report.entries >= MAX_ENTRIES {
                self.report.parsed = false;
                add_finding(
                    &mut self.report,
                    "entry-count-limit",
                    "error",
                    None,
                    format!("archive exceeds the {} entry limit", MAX_ENTRIES),
                );
                break;
            }

            if !valid_checksum(header) {
                self.report.parsed = false;
                add_finding(
                    &mut self.report,
                    "malformed-header",
                    "error",
                    None,
                    format!("invalid checksum at byte offset {offset}"),
                );
                break;
            }

            let magic = &header[257..263];
            let is_v7 = magic.iter().all(|byte| *byte == 0);
            let is_ustar = magic.starts_with(b"ustar");
            if !is_v7 && !is_ustar {
                self.report.parsed = false;
                add_finding(
                    &mut self.report,
                    "unsupported-tar-header",
                    "error",
                    None,
                    "tar header magic is neither V7 nor ustar",
                );
                break;
            }

            let name_field = decode_field(&header[0..100]);
            let mode = match parse_octal(&header[100..108]) {
                Some(value) => value,
                None => {
                    self.report.parsed = false;
                    add_finding(
                        &mut self.report,
                        "malformed-header",
                        "error",
                        None,
                        format!("invalid mode field at byte offset {offset}"),
                    );
                    break;
                }
            };
            let size = match parse_octal(&header[124..136]) {
                Some(value) => value,
                None => {
                    self.report.parsed = false;
                    add_finding(
                        &mut self.report,
                        "malformed-header",
                        "error",
                        None,
                        format!("invalid size field at byte offset {offset}"),
                    );
                    break;
                }
            };
            let link_field = decode_field(&header[157..257]);
            let prefix_field = decode_field(&header[345..500]);
            let name = if prefix_field.value.is_empty() {
                name_field.value.clone()
            } else if name_field.value.is_empty() {
                prefix_field.value.clone()
            } else {
                format!("{}/{}", prefix_field.value, name_field.value)
            };
            let typeflag = if header[156] == 0 { b'0' } else { header[156] };
            let linkname = link_field.value;
            self.report.entries += 1;
            self.report.bytes_scanned = (offset + BLOCK_SIZE) as u64;

            if name_field.invalid_utf8 || prefix_field.invalid_utf8 || link_field.invalid_utf8 {
                self.report.parsed = false;
                add_finding(
                    &mut self.report,
                    "invalid-encoding",
                    "error",
                    Some(name.clone()),
                    "a tar text field is not valid UTF-8",
                );
            }

            let _normalized_name = inspect_member_path(&mut self.report, &mut self.seen, &name);
            if typeflag == b'0' && mode & 0o111 != 0 {
                add_finding(
                    &mut self.report,
                    "executable-permission",
                    "warning",
                    Some(name.clone()),
                    format!("mode {mode:o} grants one or more execute bits"),
                );
            }

            match typeflag {
                b'1' => {
                    if linkname.is_empty() {
                        add_finding(
                            &mut self.report,
                            "empty-link-target",
                            "error",
                            Some(name.clone()),
                            "hard-link entry has an empty link target",
                        );
                    } else if link_escapes_root("", &linkname) {
                        add_finding(
                            &mut self.report,
                            "hardlink-outside-root",
                            "error",
                            Some(name.clone()),
                            format!("hard-link target {linkname:?} escapes the archive root"),
                        );
                    } else {
                        self.hardlinks
                            .push((name.clone(), normalize_archive_path(&linkname)));
                    }
                }
                b'2' => {
                    if linkname.is_empty() {
                        add_finding(
                            &mut self.report,
                            "empty-link-target",
                            "error",
                            Some(name.clone()),
                            "symbolic-link entry has an empty link target",
                        );
                    } else {
                        let parent = name.rsplit_once('/').map(|(value, _)| value).unwrap_or("");
                        if link_escapes_root(parent, &linkname) {
                            add_finding(
                                &mut self.report,
                                "symlink-outside-root",
                                "error",
                                Some(name.clone()),
                                format!(
                                    "symbolic-link target {linkname:?} escapes the archive root"
                                ),
                            );
                        }
                    }
                }
                b'3' | b'4' | b'6' | b'7' => {
                    add_finding(
                        &mut self.report,
                        "special-file",
                        "error",
                        Some(name.clone()),
                        format!(
                            "typeflag {:?} requests a special filesystem node",
                            typeflag as char
                        ),
                    );
                }
                b'x' | b'g' | b'L' | b'K' => {
                    self.report.parsed = false;
                    add_finding(
                        &mut self.report,
                        "unsupported-metadata",
                        "error",
                        Some(name.clone()),
                        format!(
                            "tar metadata typeflag {:?} is outside the deliberately small MVP",
                            typeflag as char
                        ),
                    );
                }
                b'0' | b'5' => {}
                _ => {
                    self.report.parsed = false;
                    add_finding(
                        &mut self.report,
                        "unsupported-entry-type",
                        "error",
                        Some(name.clone()),
                        format!("tar typeflag {:?} is not supported", typeflag as char),
                    );
                }
            }

            if size > MAX_ENTRY_BYTES {
                self.report.parsed = false;
                add_finding(
                    &mut self.report,
                    "oversized-entry",
                    "error",
                    Some(name.clone()),
                    format!(
                        "entry declares {size} bytes, above the {} byte entry limit",
                        MAX_ENTRY_BYTES
                    ),
                );
                break;
            }

            let next_declared = match self.report.declared_bytes.checked_add(size) {
                Some(value) => value,
                None => MAX_DECLARED_BYTES.saturating_add(1),
            };
            if next_declared > MAX_DECLARED_BYTES {
                self.report.parsed = false;
                add_finding(
                    &mut self.report,
                    "archive-bomb-limit",
                    "error",
                    Some(name.clone()),
                    format!(
                        "declared payload exceeds the {} byte archive limit",
                        MAX_DECLARED_BYTES
                    ),
                );
                break;
            }
            self.report.declared_bytes = next_declared;

            let padded = match padded_size(size) {
                Some(value) => value,
                None => {
                    self.report.parsed = false;
                    add_finding(
                        &mut self.report,
                        "malformed-header",
                        "error",
                        Some(name.clone()),
                        "entry size cannot be represented as a tar block span",
                    );
                    break;
                }
            };
            let payload_start = offset + BLOCK_SIZE;
            let next = match payload_start.checked_add(padded) {
                Some(value) => value,
                None => {
                    self.report.parsed = false;
                    add_finding(
                        &mut self.report,
                        "malformed-header",
                        "error",
                        Some(name.clone()),
                        "entry payload offset overflowed",
                    );
                    break;
                }
            };
            if next > self.bytes.len() {
                self.report.parsed = false;
                self.report.bytes_scanned = self.bytes.len() as u64;
                add_finding(
                    &mut self.report,
                    "truncated-entry",
                    "error",
                    Some(name),
                    format!("entry payload ends at byte {next}, beyond archive length"),
                );
                break;
            }
            offset = next;
            self.report.bytes_scanned = offset as u64;
        }

        if !terminated && self.report.parsed {
            self.report.parsed = false;
            add_finding(
                &mut self.report,
                "missing-end-marker",
                "error",
                None,
                "archive does not contain two terminating zero blocks",
            );
        }
        if terminated && self.bytes[offset..].iter().any(|byte| *byte != 0) {
            self.report.parsed = false;
            add_finding(
                &mut self.report,
                "trailing-data",
                "error",
                None,
                "nonzero data follows the tar end marker",
            );
        }

        for (path, target) in self.hardlinks {
            if !self.seen.contains_key(&target) {
                add_finding(
                    &mut self.report,
                    "missing-hardlink-target",
                    "error",
                    Some(path),
                    format!("hard-link target {target:?} is not present in the archive"),
                );
            }
        }

        finalize(&mut self.report);
        self.report
    }
}

struct DecodedField {
    value: String,
    invalid_utf8: bool,
}

fn decode_field(field: &[u8]) -> DecodedField {
    let end = field
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(field.len());
    match std::str::from_utf8(&field[..end]) {
        Ok(value) => DecodedField {
            value: value.trim_end_matches(' ').to_owned(),
            invalid_utf8: false,
        },
        Err(_) => DecodedField {
            value: String::from_utf8_lossy(&field[..end])
                .trim_end_matches(' ')
                .to_owned(),
            invalid_utf8: true,
        },
    }
}

fn parse_octal(field: &[u8]) -> Option<u64> {
    let trimmed = field
        .iter()
        .copied()
        .filter(|byte| *byte != 0 && *byte != b' ')
        .collect::<Vec<_>>();
    if trimmed.is_empty() {
        return Some(0);
    }
    if trimmed.iter().any(|byte| !(b'0'..=b'7').contains(byte)) {
        return None;
    }
    let mut value = 0u64;
    for byte in trimmed {
        value = value.checked_mul(8)?.checked_add(u64::from(byte - b'0'))?;
    }
    Some(value)
}

fn valid_checksum(header: &[u8]) -> bool {
    let stored = parse_octal(&header[148..156]);
    let mut sum = 0u64;
    for (index, byte) in header.iter().enumerate() {
        sum += if (148..156).contains(&index) {
            u64::from(b' ')
        } else {
            u64::from(*byte)
        };
    }
    stored == Some(sum)
}

fn padded_size(size: u64) -> Option<usize> {
    let blocks = size.checked_add((BLOCK_SIZE - 1) as u64)? / BLOCK_SIZE as u64;
    blocks.checked_mul(BLOCK_SIZE as u64)?.try_into().ok()
}

fn inspect_member_path(
    report: &mut Report,
    seen: &mut BTreeMap<String, String>,
    name: &str,
) -> String {
    if name.is_empty() {
        add_finding(
            report,
            "empty-path",
            "error",
            None,
            "archive member has an empty path",
        );
    }
    if name.starts_with('/') || Path::new(name).is_absolute() {
        add_finding(
            report,
            "absolute-path",
            "error",
            Some(name.to_owned()),
            "archive member path starts at the host filesystem root",
        );
    }
    if name.contains('\0') {
        add_finding(
            report,
            "nul-in-path",
            "error",
            Some(name.to_owned()),
            "archive member path contains a NUL byte",
        );
    }
    if name.split('/').any(|component| component == "..") {
        add_finding(
            report,
            "path-traversal",
            "error",
            Some(name.to_owned()),
            "archive member path contains a parent-directory component",
        );
    }

    let normalized = normalize_archive_path(name);
    if let Some(previous) = seen.get(&normalized) {
        let kind = if previous == name {
            "duplicate-path"
        } else {
            "path-normalization-collision"
        };
        add_finding(
            report,
            kind,
            "error",
            Some(name.to_owned()),
            format!("normalized path {normalized:?} was already used by {previous:?}"),
        );
    } else {
        seen.insert(normalized.clone(), name.to_owned());
    }
    normalized
}

fn normalize_archive_path(path: &str) -> String {
    let nfc = path.nfc().collect::<String>();
    nfc.split('/')
        .filter(|component| !component.is_empty() && *component != ".")
        .collect::<Vec<_>>()
        .join("/")
}

fn link_escapes_root(base: &str, target: &str) -> bool {
    if target.starts_with('/') || target.contains('\0') {
        return true;
    }
    let joined = if base.is_empty() {
        target.to_owned()
    } else if target.is_empty() {
        base.to_owned()
    } else {
        format!("{base}/{target}")
    };
    let normalized = joined.nfc().collect::<String>();
    let mut depth = 0usize;
    for component in normalized.split('/') {
        match component {
            "" | "." => {}
            ".." => {
                if depth == 0 {
                    return true;
                }
                depth -= 1;
            }
            _ => depth += 1,
        }
    }
    false
}

fn add_finding(
    report: &mut Report,
    kind: &str,
    severity: &str,
    path: Option<String>,
    detail: impl Into<String>,
) {
    report.findings.push(Finding {
        kind: kind.to_owned(),
        severity: severity.to_owned(),
        path,
        detail: detail.into(),
    });
}

fn finalize(report: &mut Report) {
    if !report.parsed {
        report.verdict = "unresolved".to_owned();
        report.safe_to_extract = false;
    } else if report.findings.is_empty() {
        report.verdict = "safe".to_owned();
        report.safe_to_extract = true;
    } else {
        report.verdict = "unsafe".to_owned();
        report.safe_to_extract = false;
    }
}
