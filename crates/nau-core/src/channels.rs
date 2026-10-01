//! Store channel/track vocabulary shared by the image build and the chart
//! checks (ADR-0051 Decision 3: shared vocabulary moves DOWN into
//! nau-core — this math is consumed by both `image::staging` and the
//! chart lint battery).

/// The `piboot` bootloader type name (image declarations' `bootloader.type`).
pub const BOOTLOADER_PIBOOT: &str = "piboot";

/// Derive the store channel track from an image base name:
/// "core22" → Some("22"), "core26" → Some("26"); bases without a numeric
/// series ("core", custom bases) derive nothing.
pub fn base_track(base_name: &str) -> Option<&str> {
    let series = base_name.strip_prefix("core")?;
    if !series.is_empty() && series.bytes().all(|b| b.is_ascii_digit()) {
        Some(series)
    } else {
        None
    }
}

/// Replace the track of a "track/risk" (or bare risk) channel, keeping the
/// risk: "latest/stable" + track "22" → "22/stable"; "stable" → "22/stable".
pub fn channel_on_track(channel: &str, track: &str) -> String {
    // Mirrors the StoreClient channel parse: one part is a risk, two parts
    // are track/risk.
    let risk = channel.split('/').nth(1).unwrap_or(channel);
    format!("{track}/{risk}")
}

/// The effective store channel for a kernel/gadget image snap (ADR-0019).
///
/// An author-pinned channel (`channel` opt on the pin entry) wins verbatim
/// and marks the override; otherwise the image base's track replaces the
/// default track ("core22" + "latest/stable" → "22/stable" — the
/// `latest` kernel line carries the legacy 4.4 ESM payloads); a base with
/// no numeric series leaves the channel untouched.
///
/// Returns `(channel, override_used)`.
pub fn image_snap_channel(
    default_channel: &str,
    base_name: &str,
    explicit: Option<&str>,
) -> (String, bool) {
    if let Some(explicit) = explicit {
        return (explicit.to_string(), true);
    }
    match base_track(base_name) {
        Some(track) => (channel_on_track(default_channel, track), false),
        None => (default_channel.to_string(), false),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base_track_derives_the_numeric_series() {
        assert_eq!(base_track("core22"), Some("22"));
        assert_eq!(base_track("core26"), Some("26"));
        assert_eq!(base_track("core"), None);
        assert_eq!(base_track("core- custom"), None);
    }

    #[test]
    fn channel_on_track_keeps_the_risk() {
        assert_eq!(channel_on_track("latest/stable", "22"), "22/stable");
        assert_eq!(channel_on_track("stable", "22"), "22/stable");
    }

    #[test]
    fn image_snap_channel_explicit_wins_and_derives_from_base() {
        let (ch, ov) = image_snap_channel("latest/stable", "core22", Some("beta/stable"));
        assert_eq!(ch, "beta/stable");
        assert!(ov);
        let (ch, ov) = image_snap_channel("latest/stable", "core22", None);
        assert_eq!(ch, "22/stable");
        assert!(!ov);
        let (ch, ov) = image_snap_channel("latest/stable", "core", None);
        assert_eq!(ch, "latest/stable");
        assert!(!ov);
    }
}
