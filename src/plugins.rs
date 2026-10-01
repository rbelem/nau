//! The built-in plugin registry (ADR-0014) — moved down to nau-core
//! (issue #326: the chart SnapMeta parse path expands plugin parts too).
//! Re-exported wholesale so every `crate::plugins::…` path keeps
//! resolving unchanged.

pub use nau_core::plugins::*;

// Drift guard (issue #326): the eval prelude builds its plugin table from
// `nau_core::plugins::PLUGIN_NAMES`; the registry must never diverge from
// that list. This test fails the gate the moment a plugin is added to one
// side only.
#[cfg(test)]
mod plugin_registry_drift_guard {
    #[test]
    fn core_plugin_names_match_the_build_registry() {
        let mut names = super::plugin_names();
        names.sort_unstable();
        assert_eq!(
            names,
            nau_core::plugins::PLUGIN_NAMES.to_vec(),
            "nau_core::plugins::PLUGIN_NAMES drifted from the PLUGINS registry — \
             update the core list in the same change"
        );
    }
}
