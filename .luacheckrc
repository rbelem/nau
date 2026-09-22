-- luacheck configuration for the shuttle recipe corpus.
--
-- Recipes under pkgs/ are Lua 5.4 modules returning a single table
-- literal. The shuttle eval prelude (src/shuttle-prelude.d.luau) injects
-- the DSL globals at runtime — snap, merge, pin, index, app, image,
-- node, fetch — so luacheck sees them as provided globals, matching the
-- typed prelude one-for-one.
--
-- src/shuttle-prelude.d.luau is NOT lintable here: it is Luau (declare
-- statements, type annotations) and luacheck's parser rejects it
-- ("expected '=' near 'snap'" at the first declare). It is covered by
-- stylua (syntax = "All") and the check-stage Luau gate instead.

std = "lua54"

-- Long shell-command strings and tarball URLs must stay byte-identical,
-- so lines cannot be hard-wrapped at an arbitrary width. Prose comments
-- are wrapped manually by convention; the only lines that exceed a sane
-- width are string literals (verified: every line >120 chars in the
-- corpus carries a string). Disable the length check instead of
-- sprinkling per-file ignores over ~70 recipes.
max_line_length = false

globals = {
    "snap",
    "merge",
    "pin",
    "index",
    "app",
    "image",
    "node",
    "fetch",
}

exclude_files = {
    "src/shuttle-prelude.d.luau",
}
