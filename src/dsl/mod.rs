/// The injected Lua globals source (snap(), app(), etc.).
///
/// Loaded into the mlua context before evaluating the user's shuttle.lua.
pub const INIT_LUA: &str = include_str!("init.lua");

/// The full eval prelude: the DSL globals plus the built-in plugin registry
/// names (ADR-0014 Decision 3 — the Lua layer checks only that a part's
/// `plugin` is a known name; deep option validation stays in Rust).
pub fn prelude() -> String {
    let names: Vec<String> = crate::plugins::plugin_names()
        .into_iter()
        .map(|name| format!("{name} = true"))
        .collect();
    format!("{INIT_LUA}\nshuttle_plugins = {{ {} }}\n", names.join(", "))
}

#[cfg(test)]
mod tests {
    #[test]
    fn test_prelude_injects_plugin_registry() {
        let prelude = super::prelude();
        assert!(prelude.starts_with(super::INIT_LUA));
        for name in crate::plugins::plugin_names() {
            assert!(
                prelude.contains(&format!("{name} = true")),
                "prelude must inject plugin '{name}': {prelude}"
            );
        }
    }
}
