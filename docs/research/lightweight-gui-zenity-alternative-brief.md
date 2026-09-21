# Lightweight GUI libs for a zenity alternative — brief

> **Purpose:** Pick the GUI stack for a Rust `zenity` replacement (CLI tool that pops dialogs from shell scripts). Dense comparison across footprint, looks, dialog ergonomics, Wayland, and maintenance, with primary-source citations. Written September 2026.
>
> **Sources:** docs.rs, project READMEs/Cargo.tomls on GitHub, crates.io API, Arch man page for zenity 4.2.2. Numbers I could not verify against a primary source are marked **UNVERIFIED**.

## Answer

**Top pick: egui/eframe with the `glow` backend** — it is the only candidate that is simultaneously tiny in ceremony (one short-lived window, no event-model gymnastics), actively maintained (0.36.2 released Sep 8, 2026), works natively on Wayland and X11 via winit, ships bundled dark-mode styling that looks contemporary rather than native-retro, and is MIT/Apache-licensed. The decisive trade-off: **egui is not native-looking** — it draws its own widgets and doesn't follow your GNOME/KDE theme. **Runner-up: Slint under GPLv3** — it *does* look modern and near-native (fluent/cosmic/cupertino/material styles), has embedded-heritage footprint, and its GPL option is fully compatible with a GPL zenity alternative; the cost is a DSL to learn and the largest dependency tree of the "light" candidates. **The pragmatic "don't build" option: wrap the platform dialog tool** — `rfd`/`native-dialog` only cover message + file dialogs (zenity has ~15 dialog types, and on Linux both crates literally shell out to zenity/KDialog/YAD), so wrapping only makes sense if you accept the target machine already having a dialog tool installed — at which point you've built a worse `zenity`. If full zenity parity + perfect native look is the actual goal, gtk4-rs/relm4 is the honest answer, and it's the heavyweight baseline everything else is measured against.

## Comparison table

| Candidate | Backend | Binary size | Cold start | RAM | Dialog ergonomics | Modern looks | Wayland | Maintenance | License |
|---|---|---|---|---|---|---|---|---|---|
| **egui/eframe** (glow) | winit + OpenGL (glow) or wgpu | ~10–15 MB with glow (self-reported direction; exact number UNVERIFIED) [eframe Cargo.toml cites #5889: "switching from wgpu to glow can significantly reduce your binary size"] | Fast; no system service startup (UNVERIFIED, but pure userspace GL) | Low-moderate (UNVERIFIED) | Immediate-mode; one-window app is trivial | 4/5 — own style engine, dark default, rounded; *not* native theming | Yes — `wayland` + `x11` features, wayland on by default | ★ 30.6k, 0.36.2 Sep 2026, very active | MIT OR Apache-2.0 |
| **Slint** | femtovg (GL) / skia / software / Qt | Small (embedded heritage, runs on RP2040-class HW per README) — exact number UNVERIFIED | Fast (UNVERIFIED) | Low (UNVERIFIED) | Declarative `.slint` DSL; fine for dialog-shaped UIs | 5/5 — fluent/cosmic/cupertino/material/qt widget styles | Yes (winit backend) | ★ 23.9k, v1.18.0 Sep 2026, company-backed (SixtyFPS) | GPL-3.0 **or** royalty-free (attribution) **or** commercial |
| **iced** | wgpu or tiny-skia (software) | Larger with wgpu (wgpu is the main size/speed cost in Rust GUIs; UNVERIFIED) | Moderate (wgpu init; UNVERIFIED) | Moderate (UNVERIFIED) | Elm arch (state/message/update) — ceremony for a one-shot dialog | 4/5 — own rendering, clean default look, not native | Yes via winit | ★ 31.5k, 0.14.0 Dec 2025, active; "currently experimental software" (README) | MIT |
| **fltk-rs** | FLTK C++ → X11/GL (Wayland hybrid feature) | Small binary, but ~16 shared runtime libs on Linux (README dep list) | Very fast (classic C toolkit; UNVERIFIED) | Very low (UNVERIFIED) | Retained widgets, dialog widgets built in (message/alert/password/input/choice) | 2/5 — 5 built-in schemes + fltk-theme; modernizable but dated | Yes, opt-in `use-wayland` feature (hybrid backend) | 1.5.23 May 2026, steady, single-maintainer-dominated | MIT |
| **gtk4-rs / relm4** | GTK4 (rendering + system theme) | Tiny binary, **huge** shared closure (GTK4+glib+pango+cairo+adwaita; UNVERIFIED count) | Slowest — GTK init + theme loading (UNVERIFIED) | Highest (UNVERIFIED) | Perfect — this is literally zenity's own stack | 5/5 — native libadwaita on GNOME | Yes, native | Extremely active (GNOME project) | MIT for bindings; GTK4 LGPL-2.1+ |
| **libui-ng-rs bindings** | Native toolkits (GTK on Linux) | Small | Fast (UNVERIFIED) | Low (UNVERIFIED) | Simple control tray; limited widgets | 3/5 — native controls, but GTK-via-libui not libadwaita | Follows GTK | **Dead**: `libui-ng-sys` last published **2023-01-28** (crates.io API) | MPL-2.0 |
| **rfd** | None — native dialogs (XDG portal default / GTK3 feature) | Smallest — no toolkit shipped | Instant-ish; but needs portal D-Bus round-trip | Negligible | One call per dialog, but only file + message types | 5/5 (it *is* the platform dialog) | Yes (portal) | 0.17.2 Jan 2026, active, 830★ | MIT/Apache? (repo) — UNVERIFIED |
| **native-dialog** | None — shells out to **zenity/KDialog/YAD** on Linux | Smallest | Adds a process spawn | Negligible | File + message only | Inherits zenity's | Inherits | Check crates.io — activity low (UNVERIFIED) | MIT (docs.rs) |

## What zenity actually does (the parity checklist)

From the man page for zenity 4.2.2 ([man.archlinux.org/man/zenity.1](https://man.archlinux.org/man/zenity.1)) — "a program that will display GTK+ dialogs, and return (either in the return code, or on standard output) the users input":

- **Message dialogs:** info, error, warning, question (exit codes 0/1/5 for OK/Cancel/timeout)
- **Entry:** text entry with optional `--hide-text` (password), returns typed text on stdout
- **File selection:** open/save, multiple select, directory-only, filters, separator
- **List:** columns from stdin, `--checklist`, `--radiolist`, multi-select, column printing
- **Progress:** percentage on stdin, `--pulsate`, auto-close, kill-parent-on-cancel
- **Notification:** passive desktop notification, `--listen` on stdin
- **Plus:** calendar, scale (slider), text-info (stdin, I-read-and-agree checkbox), color selection, password (+username), forms (entries, password fields, calendar, list, combo — since 4.2)
- **Generic:** `--timeout`, custom button labels, extra buttons, modal hint

Any "alternative" that covers message+entry+file+list+progress+notification hits the 90% use case; forms/calendar/scale/color are long-tail.

## Per-candidate notes

### egui / eframe — **recommended**
- **Footprint:** eframe defaults to **wgpu**, but the feature docs are explicit: *"Switching from `wgpu` (the default) to `glow` can significantly reduce your binary size"* ([eframe/Cargo.toml](https://github.com/emilk/egui/blob/master/crates/eframe/Cargo.toml), referencing [issue #5889](https://github.com/emilk/egui/issues/5889)). A glow-only build avoids the entire wgpu/DX12/Vulkan stack. Exact MB figure: **UNVERIFIED** — publish a `--release` + strip measurement before committing.
- **Startup:** no toolkit init beyond GL context + winit; fonts are bundled via `include_bytes!` (`default_fonts` feature). Should feel instant for script use; **no primary benchmark found**.
- **Looks:** own immediate-mode style engine — dark theme default, rounded corners, HiDPI-correct (logical points, per README "Conventions and design choices"). It will not match libadwaita; it will not look like 2003. Fonts (Hack, Ubuntu, emoji) bundled, system-font fallback via `system_fonts` feature (default).
- **Dialog fit:** immediate mode is ideal for short-lived single-window tools — one `eframe::run_native`, one `update()` returning based on button clicks, process exits. No Elm message plumbing (iced) and no DSL (Slint). File dialogs delegated to `rfd` (official FAQ recommendation).
- **Platform:** `wayland` and `x11` are first-class features; wayland is in the **default feature set** ("Required for Linux support (including CI!)" — Cargo.toml). No D-Bus/systemd hard deps.
- **Maintenance:** 0.36.2 released 2026-09-08, pushed 2026-09-20, 30.6k stars, sponsored by Rerun. Low risk.
- **License:** MIT OR Apache-2.0 — compatible with GPL-3.0-only shuttle-style projects.
- **Weakness (honest):** non-native look; accessibility via AccessKit is on by default in eframe, which is good, but Linux accessibility support still lags Windows/macOS (README FAQ).

### Slint — runner-up
- **Footprint:** design goal "Lightweight … smartphone-like user experience on any device"; runs on STM32/RP2040 per README — strong evidence of a small runtime, but **no desktop binary-size number verified**.
- **Looks:** the strongest of the non-native candidates: compiled-in widget styles include **fluent, material, cosmic, cupertino, qt** (verified in the repo tree: `internal/compiler/widgets/{fluent,material,cosmic,cupertino,qt}`), plus a Qt QStyle backend when Qt is installed for true native widgets. Dark mode and HiDPI supported.
- **License:** triple-licensed — **GPLv3 (free for open source, embedded included)**, royalty-free license for proprietary desktop apps *with* Slint attribution, or paid commercial ([LICENSE.md](https://raw.githubusercontent.com/slint-ui/slint/master/LICENSE.md)). For a GPL zenity alternative the GPL option is a non-issue; only relevant if you ever want to relicense.
- **Dialog fit:** `.slint` markup + Rust glue; slight overhead for a throwaway dialog but perfectly workable; stable 1.x API explicitly promised.
- **Maintenance:** v1.18.0 released 2026-09-16; company-backed (SixtyFPS GmbH); 23.9k stars.
- **Weakness (honest):** you're adopting a DSL and a compiler; compile times heavier than egui (UNVERIFIED but widely reported); more moving parts than eframe for one dialog.

### iced
- Two renderers: `wgpu` (Vulkan/Metal/DX12) and `tiny-skia` (software fallback) — README. Use tiny-skia for a small dialog binary; **size numbers UNVERIFIED**.
- **Dialog fit is the problem:** Elm architecture requires state/message/update/view scaffolding even for "show a window, read one field, exit." Doable, just the most ceremony per dialog of the Rust options.
- README carries its own warning: *"Iced is currently experimental software."* Last stable 0.14.0 (Dec 2025), very active master.
- No native theming (own renderer). Wayland via winit.

### fltk-rs
- Genuinely light at runtime (C++ FLTK; README lists the ~16 X11/pango/cairo shared libs as the whole dependency surface), very fast startup (**UNVERIFIED**, classic-toolkit behavior), tiny binary.
- Built-in dialog widgets cover a surprising amount of the zenity checklist: message, alert, password, input, choice, native file dialog, color chooser (README widget list). Progress bar, browsers (list), table widgets exist too.
- **Looks are the weak point:** 5 built-in schemes (Base/Gtk/Gleam/Plastic/Oxy) plus `fltk-theme` (dark, tan, aero…) — modernizable, but it will never pass for libadwaita, and honest assessment is "clean 2010," not "modern GNOME."
- **Wayland:** opt-in `use-wayland` feature provides a hybrid backend (README) — real but secondary; X11 remains the primary path.
- **Build cost:** CMake + C++17 toolchain required (bundled prebuilt FLTK available on x86_64/aarch64). Maintenance steady (1.5.23, May 2026).

### gtk4-rs / relm4 — the baseline
This is what the problem is *defined* against: zenity itself is "a program that will display GTK+ dialogs" (man page). Perfect native look, every dialog type trivially available, native Wayland, GNOME-backed maintenance. Cost: the largest dynamic closure of any option — GTK4 + GLib + GObject + Pango + Cairo + GDK-Pixbuf (+ libadwaita if you want HSCI colors/rounded corners), and the slowest cold start of the set (**numbers UNVERIFIED** — but this is the "heavyweight" pole of the comparison by construction). If disk/runtime deps on the user's machine are acceptable, this is the *lowest-effort full-parity* path, not the *lightest*.

### libui-ng bindings — avoid
`libui-ng-sys` last published **2023-01-28** (crates.io API: max_version 0.7.0, published_by a deleted-user ghost account). Native controls and a tiny footprint would be ideal, but the project is unmaintained and the risk of rotting on modern Wayland/GNOME is high. Not recommended.

### rfd / native-dialog / msgbox — the "wrap the platform" family
- **rfd** ([docs.rs/rfd](https://docs.rs/rfd/latest/rfd/)): file open/save/multi/folder + filters + a `MessageDialog` (info/warning/error, OK/Cancel/YesNo/OkCustom). Linux default backend is **XDG Desktop Portal via libdbus**, with **zenity as the runtime fallback** ("Zenity is also required to display message dialogs" — docs.rs). No entry, no list, no progress, no calendar, no notification. Perfect native look because it *is* the platform dialog.
- **native-dialog** ([docs.rs](https://docs.rs/native-dialog/latest/native_dialog/)): file choosers + message boxes; on Linux/BSD *"requires either Zenity, KDialog, or YAD being installed; otherwise the `MissingDep` error is returned."* I.e., it doesn't even ship a dialog on Linux — it spawns an existing dialog tool.
- **Key insight for this project:** on Linux, "lightweight native dialog" and "wrap zenity" converge — both crates end up delegating to the same GTK/portal machinery zenity itself uses. A wrapper tool is only lighter in *installed bytes* if you depend on the target machine's dialog tool, which means your zenity alternative requires zenity. That's circular.
- **msgbox:** tiny message-box-only crate; upstream repo/activity **UNVERIFIED** (my repo lookup failed). Message dialogs only — a strict subset of rfd. Skip.
- **The `zenity` crate on crates.io is a red herring:** despite the name it is "Yet Another Spinner Lib" — a *terminal* spinner/progress-bar library, no GUI at all ([docs.rs/zenity](https://docs.rs/zenity/latest/zenity/)).
- **YAD** (github.com/v1cont/yad) and **kdialog** (KDE) are the reference points for feature scope: both are fork-of/sibling-of zenity with *more* dialog types — evidence that the CLI-dialog-tool niche wants full parity, which favors a real toolkit over a wrapper.

## Non-Rust survey (short)

| Toolkit | Verdict for this use case |
|---|---|
| **Tk (C/Python)** | Ship-with-Python ergonomics are nice, but ttk theming on Linux is dated (no libadwaita adherence); tk widgets render acceptably but recognizably 2003. Rust bindings (rust-tk) are low-activity — UNVERIFIED, didn't deep-check. |
| **FLTK (C++)** | Same as fltk-rs above — it's the same library. Lightest real toolkit here. |
| **IUP** | Smaller community than FLTK, native GTK look on Linux, minimal maintenance activity — risky (UNVERIFIED maintenance). |
| **Dear ImGui (C++)** | The model egui copied; C++ would fight the Rust ecosystem for zero benefit over egui. |
| **nuklear** | Single-header immediate mode, even lower-level than ImGui (you own the backend); styling work would dwarf the project. No. |
| **Go Fyne** | Good looks (material-ish), single binary, but drags the Go runtime (~15–25 MB binaries, slower start than Rust — UNVERIFIED) and puts a Go toolchain in your project. |
| **Go Wails** | Ships a webview + HTML/CSS UI; beautiful, but heavyweight and the wrong shape for a 5-line dialog from a shell script. |

## Recommendation

1. **Top pick — egui/eframe (glow backend) + rfd (portal feature) for file dialogs.** One Rust binary, no GTK closure, wayland+X11 in the default features, MIT/Apache so it can live under GPL-3.0-only, and immediate-mode is the closest Rust GUI model to "parse argv → show window → print stdout → exit." Accept that it looks like *good dark-mode egui*, not like the user's desktop theme. Before committing, measure the actual release binary + cold start (my size/startup numbers above are marked UNVERIFIED).
2. **Runner-up — Slint under GPLv3** if native-ish theming is non-negotiable: fluent/cosmic/cupertino/material styles, embedded-heritage footprint, company-backed, GPL option fits a GPL tool. Cost: the DSL and a slightly heavier build.
3. **The "don't build, just wrap" option:** if the real requirement is "perfect native dialogs with zero new code," the answer is not rfd — it's **admitting zenity/YAD/kdialog already exist**, and a Rust wrapper would just re-depend on them (that is literally how rfd and native-dialog work on Linux). Wrap only if the goal is a nicer CLI on top of *an existing* dialog tool; it cannot be the zenity replacement itself.
4. **Full-parity heavyweight:** gtk4-rs/relm4 if you decide 100% zenity parity + libadwaita look beats lightness. It's the only path where every dialog in the man-page checklist is a stock widget.

**Skip:** libui-ng (dead since 2023), iced for this shape (Elm ceremony, experimental), fltk-rs (light but look ceiling too low for "modern looks" as a stated requirement), the `zenity` crate (it's a terminal spinner).

## Addendum — existing zenity-like tools by toolkit (follow-up, Sep 20 2026)

Does a zenity-like CLI already exist on the stacks above? Verified via GitHub/crates.io APIs:

- **zenity-rs** ([QaidVoid/zenity-rs](https://github.com/QaidVoid/zenity-rs)) — **yes, and it uses no toolkit**: pure-Rust renderer (tiny-skia + ab_glyph, x11rb/wayland-client) covering ~the full zenity checklist. v0.3.0 Sep 9 2026, very active, ~1.5 MB musl static binary. It already occupies the "zenity without GTK" slot.
- **egui/eframe** — no CLI tool exists. Building blocks: [egui-file-dialog](https://crates.io/crates/egui-file-dialog) (mature, active) + [egui_dialogs](https://github.com/a-littlebit/egui_dialogs).
- **Slint** — nothing (zero repo hits). **iced** — only `iceity`, dead toy (2022).
- **FLTK** — `fltk-dialog` (C++, abandoned ~2020); `xdialog` crate is a library with no CLI binary.
- **GTK/Qt** — mature: zenity 4.2.1, yad v15.0 (2026-07), kdialog, qarma 1.1.1 (revived, Qt6).
- **Go** — [ncruces/zenity](https://github.com/ncruces/zenity) is a Windows/macOS port that shells out to real zenity on Linux; no Fyne-based zenity exists.

Implication: the open lane is not "zenity without GTK" (taken by zenity-rs) but **"zenity with modern looks"** — an egui/Slint build differentiates on polish and toolkit-grade styling.

## Sources

- zenity(1) man page, 4.2.2 — https://man.archlinux.org/man/zenity.1
- egui README — https://github.com/emilk/egui (raw README fetched)
- eframe Cargo.toml (features, glow/wgpu, wayland/x11 defaults) — https://github.com/emilk/egui/blob/master/crates/eframe/Cargo.toml ; egui binary-size issue — https://github.com/emilk/egui/issues/5889
- iced README — https://github.com/iced-rs/iced
- Slint README — https://github.com/slint-ui/slint ; Slint LICENSE.md — https://github.com/slint-ui/slint/blob/master/LICENSE.md ; widget style dirs (fluent/material/cosmic/cupertino/qt) — https://github.com/slint-ui/slint/tree/master/internal/compiler/widgets
- fltk-rs README (schemes, wayland feature, runtime deps, widget list) — https://github.com/fltk-rs/fltk-rs
- rfd docs — https://docs.rs/rfd/latest/rfd/ (portal/zenity fallback, feature matrix)
- native-dialog docs — https://docs.rs/native-dialog/latest/native_dialog/ (zenity/kdialog/yad requirement)
- `zenity` crate (terminal spinner) — https://docs.rs/zenity/latest/zenity/
- libui-ng-sys crates.io record (last publish 2023-01-28) — https://crates.io/api/v1/crates/libui-ng-sys
- Release dates/activity via GitHub API: PolyMeilex/rfd (0.17.2, 2026-01-12), emilk/egui (0.36.2, 2026-09-08), iced-rs/iced (0.14.0, 2025-12-07), fltk-rs/fltk-rs (1.5.23, 2026-05-03), slint-ui/slint (v1.18.0, 2026-09-16)
- YAD — https://github.com/v1cont/yad ; KDialog — https://invent.kde.org/utilities/kdialog
