#![no_main]

use archive_lint::lint_archive_bytes;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = lint_archive_bytes("fuzz.tar", data);
});
