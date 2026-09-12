//! ESP inspection: try-boot counters live in the UKI **filename** on the EFI
//! System Partition, not in the serial console (issue #77).
//!
//! systemd-boot renames the selected UKI *before* the kernel loads: a counted
//! entry `foo+3-0.efi` becomes `foo+2-1.efi` as soon as it is chosen, so the
//! observation must come from the ESP itself. This module reads it without a
//! loop mount or root, using `sfdisk -J` to find the partition byte offset and
//! `mtools` (`mdir`) against `<img>@@<offset>`.
//!
//! The pure parsing helpers ([`parse_uki_name`], [`parse_dir_listing`],
//! [`parse_partition_offset`]) carry the unit tests; the runner-based
//! primitives go exclusively through [`CommandRunner`] so a hermetic fake can
//! drive the orchestration end to end.

use std::path::Path;

use miette::{IntoDiagnostic, WrapErr};

use crate::command::{exit_code, CommandRunner};

/// The directory on the ESP where systemd-boot discovers UKIs.
pub const ESP_UKI_DIR: &str = "/EFI/Linux";

/// A counted UKI's try-boot state: how many tries remain and how many have
/// already failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TryCounters {
    pub tries_left: u32,
    pub tries_done: u32,
}

/// A UKI filename split into its counterless base and, when present, the
/// parsed `+N-M` try-boot counters.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UkiName {
    /// The filename with any counter stripped; the input unchanged when no
    /// valid counter was found.
    pub base: String,
    /// The parsed counters, or `None` when the name carries no valid suffix.
    pub counters: Option<TryCounters>,
}

fn is_digits(s: &str) -> bool {
    !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit())
}

/// Split a UKI filename into its base and try-boot counters.
///
/// Grammar: the **last** `+` in the stem, then `<left>[-<done>]`, immediately
/// before a `.efi` suffix. The `<done>` half is optional. Anything else is
/// malformed — the name is returned with `base` set to the *original* input
/// and `counters = None`.
pub fn parse_uki_name(name: &str) -> UkiName {
    let unchanged = || UkiName {
        base: name.to_string(),
        counters: None,
    };
    let Some(stem) = name.strip_suffix(".efi") else {
        return unchanged();
    };
    let Some(plus) = stem.rfind('+') else {
        return unchanged();
    };
    let (base, spec) = stem.split_at(plus);
    let spec = &spec[1..];
    let (left, done) = match spec.split_once('-') {
        Some((left, done)) => (left, Some(done)),
        None => (spec, None),
    };
    if !is_digits(left) || done.is_some_and(|d| !is_digits(d)) {
        return unchanged();
    }
    let Ok(tries_left) = left.parse::<u32>() else {
        return unchanged();
    };
    let tries_done = match done {
        Some(d) => match d.parse::<u32>() {
            Ok(v) => v,
            Err(_) => return unchanged(),
        },
        None => 0,
    };
    UkiName {
        base: format!("{base}.efi"),
        counters: Some(TryCounters {
            tries_left,
            tries_done,
        }),
    }
}

/// Parse `mdir` output into bare directory-entry names: trim each line, drop
/// blanks, `.`, and `..`, and keep only the last `/`-separated segment.
pub fn parse_dir_listing(stdout: &str) -> Vec<String> {
    stdout
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && *line != "." && *line != "..")
        .map(|line| line.rsplit('/').next().unwrap_or(line).trim().to_string())
        .filter(|name| !name.is_empty())
        .collect()
}

/// Parse `sfdisk -J` output and return the byte offset (sector 512) of the
/// partition whose `name` equals `name`.
pub fn parse_partition_offset(json: &str, name: &str) -> miette::Result<u64> {
    let value: serde_json::Value = serde_json::from_str(json)
        .into_diagnostic()
        .wrap_err("failed to parse 'sfdisk -J' output as JSON")?;
    let partitions = value
        .get("partitiontable")
        .and_then(|t| t.get("partitions"))
        .and_then(|p| p.as_array())
        .ok_or_else(|| miette::miette!("'sfdisk -J' output has no partitiontable.partitions"))?;
    for partition in partitions {
        if partition.get("name").and_then(|n| n.as_str()) == Some(name) {
            let start = partition
                .get("start")
                .and_then(|s| s.as_u64())
                .ok_or_else(|| {
                    miette::miette!("partition '{name}' has no numeric 'start' field")
                })?;
            return Ok(start * 512);
        }
    }
    Err(miette::miette!(
        "no partition named '{name}' in 'sfdisk -J' output"
    ))
}

fn check_success(out: &crate::command::RunnerOutput, what: &str) -> miette::Result<()> {
    let code = exit_code(out);
    if code != 0 {
        return Err(miette::miette!(
            "{what} failed (exit {code}): {}",
            out.stderr.trim()
        ));
    }
    Ok(())
}

fn run(
    runner: &dyn CommandRunner,
    argv: &[String],
) -> miette::Result<crate::command::RunnerOutput> {
    runner.run(argv).into_diagnostic().wrap_err_with(|| {
        format!(
            "failed to run '{}'",
            argv.first().map(String::as_str).unwrap_or("")
        )
    })
}

/// Read the `esp` partition's byte offset from `img` with `sfdisk -J`.
pub fn esp_partition_offset(runner: &dyn CommandRunner, img: &Path) -> miette::Result<u64> {
    let argv = vec![
        "sfdisk".to_string(),
        "-J".to_string(),
        img.display().to_string(),
    ];
    let out = run(runner, &argv)?;
    check_success(&out, &format!("sfdisk -J {}", img.display()))?;
    let stdout = String::from_utf8_lossy(&out.stdout);
    parse_partition_offset(&stdout, "esp")
}

/// List a directory inside `img`'s ESP with `mdir`.
pub fn list_dir(
    runner: &dyn CommandRunner,
    img: &Path,
    offset: u64,
    dir: &str,
) -> miette::Result<Vec<String>> {
    let argv = vec![
        "mdir".to_string(),
        "-i".to_string(),
        format!("{}@@{}", img.display(), offset),
        "-b".to_string(),
        format!("::{dir}"),
    ];
    let out = run(runner, &argv)?;
    check_success(&out, &format!("mdir {dir} on {}", img.display()))?;
    let stdout = String::from_utf8_lossy(&out.stdout);
    Ok(parse_dir_listing(&stdout))
}

/// List the UKI directory on the ESP, sorted for a deterministic observation.
pub fn list_ukis(
    runner: &dyn CommandRunner,
    img: &Path,
    offset: u64,
) -> miette::Result<Vec<String>> {
    let mut names = list_dir(runner, img, offset, ESP_UKI_DIR)?;
    names.sort();
    Ok(names)
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── parse_uki_name ──

    #[test]
    fn no_counter_when_no_plus() {
        let got = parse_uki_name("ubuntu-core-pc_22.04.efi");
        assert_eq!(got.base, "ubuntu-core-pc_22.04.efi");
        assert_eq!(got.counters, None);
    }

    #[test]
    fn parses_counter_with_zero_done() {
        let got = parse_uki_name("ubuntu-core-pc_22.04+3-0.efi");
        assert_eq!(got.base, "ubuntu-core-pc_22.04.efi");
        assert_eq!(
            got.counters,
            Some(TryCounters {
                tries_left: 3,
                tries_done: 0
            })
        );
    }

    #[test]
    fn parses_various_counter_values() {
        assert_eq!(
            parse_uki_name("x+2-1.efi").counters,
            Some(TryCounters {
                tries_left: 2,
                tries_done: 1
            })
        );
        assert_eq!(
            parse_uki_name("x+0-3.efi").counters,
            Some(TryCounters {
                tries_left: 0,
                tries_done: 3
            })
        );
    }

    #[test]
    fn done_is_optional() {
        let got = parse_uki_name("x+3.efi");
        assert_eq!(got.base, "x.efi");
        assert_eq!(
            got.counters,
            Some(TryCounters {
                tries_left: 3,
                tries_done: 0
            })
        );
    }

    #[test]
    fn last_plus_wins() {
        let got = parse_uki_name("foo+bar+3-0.efi");
        assert_eq!(got.base, "foo+bar.efi");
        assert_eq!(
            got.counters,
            Some(TryCounters {
                tries_left: 3,
                tries_done: 0
            })
        );
    }

    #[test]
    fn accepts_leading_zeros() {
        let got = parse_uki_name("x+03-00.efi");
        assert_eq!(got.base, "x.efi");
        assert_eq!(
            got.counters,
            Some(TryCounters {
                tries_left: 3,
                tries_done: 0
            })
        );
    }

    #[test]
    fn malformed_is_unchanged_with_no_counters() {
        for name in [
            "foo+3-x.efi",
            "foo+-1-0.efi",
            "foo+3-0-1.efi",
            "foo+3-.efi",
            "foo++.efi",
            "foo+bar.efi",
            "foo+3-0.efi.bak",
            "foo+3-0",
        ] {
            let got = parse_uki_name(name);
            assert_eq!(
                got.base, name,
                "malformed name must stay unstripped: {name}"
            );
            assert_eq!(
                got.counters, None,
                "malformed name must have no counters: {name}"
            );
        }
    }

    // ── parse_dir_listing ──

    #[test]
    fn dir_listing_drops_dots_and_blanks() {
        let stdout = "\
.\n\
..\n\
\n\
   \n\
ubuntu-core-pc_22.04.efi\n\
ubuntu-core-pc_22.04+3-0.efi\n";
        assert_eq!(
            parse_dir_listing(stdout),
            vec![
                "ubuntu-core-pc_22.04.efi".to_string(),
                "ubuntu-core-pc_22.04+3-0.efi".to_string(),
            ]
        );
    }

    #[test]
    fn dir_listing_keeps_last_path_segment() {
        let stdout = "::/EFI/Linux/foo.efi\n/EFI/Linux/bar.efi\nbaz.efi\n";
        assert_eq!(
            parse_dir_listing(stdout),
            vec![
                "foo.efi".to_string(),
                "bar.efi".to_string(),
                "baz.efi".to_string()
            ]
        );
    }

    // ── parse_partition_offset ──

    const SFDISK_JSON: &str = r#"{
      "partitiontable": {
        "label": "gpt",
        "partitions": [
          {"node": "/dev/vda1", "start": 2048, "size": 4096, "name": "esp"},
          {"node": "/dev/vda2", "start": 6144, "size": 8192, "name": "root"}
        ]
      }
    }"#;

    #[test]
    fn partition_offset_is_bytes() {
        assert_eq!(
            parse_partition_offset(SFDISK_JSON, "esp").unwrap(),
            2048 * 512
        );
    }

    #[test]
    fn partition_offset_missing_name_errors() {
        let err = parse_partition_offset(SFDISK_JSON, "boot").unwrap_err();
        assert!(format!("{err}").contains("no partition named 'boot'"));
    }

    #[test]
    fn partition_offset_bad_json_errors() {
        assert!(parse_partition_offset("not json", "esp").is_err());
    }
}
