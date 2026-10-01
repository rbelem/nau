//! Snap meta vocabulary that needs no Lua and no chart: the mksquashfs
//! compression contract (ticket #154) and the canonical source dir name.
//! Down-moved from the chart's snap_lua ahead of PR 2 (ADR-0053) so the
//! root build machinery speaks core vocabulary directly; the chart keeps
//! a re-export shim so `nau_chart::snap_lua::*` paths survive.

/// Subdirectory of the build tree holding the shared downloaded/extracted
/// source in multi-part builds. Part work dirs are siblings of it, so the
/// name is reserved as a part name.
pub const SOURCE_DIR_NAME: &str = "source";

/// Compression choices mksquashfs accepts here (ticket #154). zstd is the
/// absent default; gzip dropped — strictly dominated by zstd (ADR-0038
/// evidence table).
const VALID_COMPRESSIONS: [&str; 3] = ["zstd", "xz", "lzo"];

/// The effective compressor: the declared value, else the zstd default
/// (ticket #154). Single point where the default lives on the Rust side.
pub fn effective_compression(compression: Option<&str>) -> &str {
    compression.unwrap_or("zstd")
}

pub fn validate_compression_choice(compression: Option<&str>) -> miette::Result<()> {
    if let Some(c) = compression {
        if !VALID_COMPRESSIONS.contains(&c) {
            return Err(miette::miette!(
                "snap meta: 'compression' must be one of: zstd, xz, lzo, got {c:?}"
            ));
        }
    }
    Ok(())
}

/// `compression_level` bounds per compressor (ticket #154): zstd 1-22,
/// lzo 1-9; rejected for xz — mksquashfs' xz wrapper does not implement
/// `-Xcompression-level`, so a declared level would silently no-op.
pub fn validate_compression_level(
    compression: Option<&str>,
    level: Option<u32>,
) -> miette::Result<()> {
    let Some(level) = level else {
        return Ok(());
    };
    match effective_compression(compression) {
        "zstd" => {
            if !(1..=22).contains(&level) {
                return Err(miette::miette!(
                    "snap meta: 'compression_level' must be between 1 and 22 for compression = \"zstd\", got {level}"
                ));
            }
        }
        "lzo" => {
            if !(1..=9).contains(&level) {
                return Err(miette::miette!(
                    "snap meta: 'compression_level' must be between 1 and 9 for compression = \"lzo\", got {level}"
                ));
            }
        }
        "xz" => {
            return Err(miette::miette!(
                "snap meta: 'compression_level' is not supported with compression = \"xz\" — \
                 mksquashfs' xz wrapper does not implement -Xcompression-level"
            ));
        }
        other => unreachable!("validated by validate_compression_choice: {other}"),
    }
    Ok(())
}
