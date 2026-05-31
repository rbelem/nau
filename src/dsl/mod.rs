/// The injected Lua globals source (snap(), app(), etc.).
///
/// Loaded into the mlua context before evaluating the user's shoot.lua.
pub const INIT_LUA: &str = include_str!("init.lua");
