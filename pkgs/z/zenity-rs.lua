-- zenity-rs: pure-Rust GUI dialogs from shell scripts (QaidVoid/
-- zenity-rs 0.3.0, published on crates.io 2026-09-09; the registry's
-- newest release, not yanked).
-- https://github.com/QaidVoid/zenity-rs (crate `zenity-rs`; NOT the
-- unrelated crates.io `zenity` spinner library by Arteiii)
--
-- THE un-blocked zenity (issue #21): zenity 4.x is hard-blocked on
-- gtk4/libadwaita (pkgs/z/zenity.lua KNOWN GAPS) and gum covers only
-- the TUI lane. zenity-rs renders the GUI lane with NO gtk at all —
-- hand-rolled windows over the native display protocols: x11rb (X11)
-- and wayland-client (Wayland), the crate's default features. The
-- whole closure is pure Rust (tiny-skia software rendering, ab_glyph
-- font rastering, kbvm keymaps): no pkg-config probes, no C libraries
-- anywhere — the runtime requires only the glibc family (statix
-- posture).
--
-- Three-way comparison:
--
-- Nix:       no nixpkgs package yet (the crate is weeks old at pin
--            time); buildRustPackage over the crates.io artifact
--            would be the shape
-- Snapcraft: no snap recipe upstream, none in the store
-- Shuttle:   declarative Lua — cargo source build against the
--            vendored deps closure. NO services declaration: an
--            interactive dialog tool invoked by scripts; the process
--            lives exactly as long as the dialog.
--
-- Port strategy: upstream releases through crates.io AND GitHub tags
-- in lockstep. The registry .crate is the canonical artifact (sha256
-- published in the registry metadata, verified here against the
-- fetched bytes: ab3f3537…4512; the crate embeds .cargo_vcs_info.json
-- pinning the release commit ade55b9), but its `.crate` suffix is not
-- in the build pipeline's extraction gate (.tar.gz/.tar.xz/.tgz only
-- — a .crate source would land unextracted in the sandbox) — so the
-- SOURCE pin is the v0.3.0 GitHub tag tree, and the registry artifact
-- serves as the CORRESPONDENCE PROOF: the Cargo.lock inside the
-- checksummed .crate is byte-identical to the tag tree's Cargo.lock
-- (compared locally), so the pinned tree is the published release.
-- The tag tree ships that Cargo.lock (v4; 87 packages = 86
-- checksummed crates.io crates + the root crate itself; zero git
-- deps), so the cargo resolver (issue #36, ADR-0017) vendors the
-- closure at FETCH time exactly as statix/pdf-inspector do, and the
-- sandbox build consumes it OFFLINE (CARGO_NET_OFFLINE + source
-- replacement at the mounted $SHUTTLE_DEPS_DIR/vendor).
-- MSRV 1.88, edition 2024 — the pool toolchain (rust 1.97.1 through
-- the /nix bind) satisfies both. build_deps: none — the pool-wide
-- source-build posture (statix.lua; flipping to the pool `rust`
-- package waits on the ADR-0018 store-exec gap).
--
-- cargo install honors upstream's [profile.release] (opt-level "z",
-- lto, codegen-units = 1, panic = abort, strip = true) and stages the
-- single bin; the declared [lib] (zenity_rs) is a library — not
-- staged.
--
-- KNOWN RISKS / GAPS (declared, accepted by the owner):
--   * YOUNG PROJECT: 0.x, single maintainer (QaidVoid), hand-rolled
--     window rendering with no widget toolkit behind it. Accepted
--     for this lane; revisit if the crate goes unmaintained.
--   * GUI NEEDS A DISPLAY: dialogs render over X11 or Wayland only.
--     On headless hosts zenity-rs produces NO output — gum (pkgs/g/
--     gum.lua) stays the TUI lane for that case. The app declares
--     the x11/wayland plugs so confinement passes the display
--     sockets; no opengl plug (tiny-skia renders in software).
--   * NOT A DROP-IN: the binary is `zenity-rs` — scripts must call
--     it by name, `zenity` stays the blocked GNOME tool. Flags are
--     zenity-style and mostly compatible (info/warning/error/
--     question, entry + --password, progress fed percentages on
--     stdin with --pulsate, file-selection incl. --save/--multiple/
--     --file-filter, list/--checklist/--radiolist, calendar,
--     text-info, scale, forms; exit codes 0/1/5/255 follow zenity),
--     with drift: no --notification/--color-selection/--about, and
--     some flags are accepted purely for compatibility (--no-markup,
--     --ellipsize, --confirm-overwrite).
--
-- Requires: glibc (pure-Rust closure). build_deps: none (host
-- toolchain through the /nix bind).

return {
    default = snap {
        name = "zenity-rs",
        version = "0.3.0",
        summary = "Display simple GUI dialogs from the command line (pure Rust)",
        description = [[
            zenity-rs lets shell scripts present graphical dialogs —
            messages, questions, text/password entry, progress, file
            selection, lists, calendar, text-info, scale, and forms —
            with zenity-style flags but NO gtk: hand-rolled windows
            over native X11 (x11rb) and Wayland (wayland-client).
            Pure-Rust closure with software rendering; the binary is
            `zenity-rs`, not a drop-in rename of zenity.
        ]],
        license = "MIT",
        grade = "stable",
        confinement = "strict",
        architectures = { "amd64" },

        source = {
            -- v0.3.0 GitHub tag tree; sha256 computed from the fetched
            -- bytes (the github.com archive endpoint and codeload serve
            -- byte-identical tarballs for this tag — both hashed).
            -- Correspondence to the published release: the Cargo.lock
            -- inside the checksummed crates.io .crate (registry sha
            -- ab3f3537…4512, release commit ade55b9) is byte-identical
            -- to this tree's Cargo.lock.
            url = "https://github.com/QaidVoid/zenity-rs/archive/refs/tags/v0.3.0.tar.gz",
            sha256 = "45829eb64927785eaf9a8fb6c84a5feec8ab0bcf0b6ed401ad0b7374db0b5cbb",
        },

        -- Cargo.lock ships in the tag tree (v4, registry-only, every
        -- crate checksummed — byte-identical to the lock inside the
        -- published .crate): vendor the closure at fetch time
        -- (issue #36).
        deps = {
            cargo = { lock = "Cargo.lock" },
        },

        build = table.concat({
            -- Cargo offline wiring (issue #36), statix.lua verbatim: a
            -- writable CARGO_HOME on the sandbox's /tmp tmpfs plus a
            -- source replacement pointing at the mounted, hash-verified
            -- vendor closure.
            "export CARGO_HOME=/tmp/shuttle-cargo-home CARGO_NET_OFFLINE=true",
            "mkdir -p \"$CARGO_HOME\"",
            "printf '[source.crates-io]\\nreplace-with = \"shuttle-vendored\"\\n\\n[source.shuttle-vendored]\\ndirectory = \"%s\"\\n' \"$SHUTTLE_DEPS_DIR/vendor\" > \"$CARGO_HOME/config.toml\"",
            -- Single root crate ([lib] zenity_rs + [[bin]] zenity-rs);
            -- cargo install stages the bin under $STAGE/bin.
            "cargo install --path $SRC --root $STAGE",
        }, " && "),

        type = "source",
        requires = { "glibc" },

        -- Snap-level plug declarations for the app's display sockets
        -- (app-level plugs must be declared here too — iwd pattern).
        plugs = {
            x11 = "x11",
            wayland = "wayland",
        },

        apps = {
            ["zenity-rs"] = app {
                command = "bin/zenity-rs",
                -- x11/wayland plugs so confinement passes the display
                -- sockets the dialogs render on. No opengl (tiny-skia
                -- software rendering) and no home plug (ADR-0011
                -- degrades it to read-only anyway — gum precedent;
                -- --file-selection saves ride that same limitation).
                plugs = { "x11", "wayland" },
            },
        },
    },
}
