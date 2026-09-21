# Lightweight TUI libs/apps for a zenity alternative — brief

> **Purpose:** Pick the terminal-UI stack for a Rust `zenity` replacement (CLI tool that shows dialogs from shell scripts). TUI sibling of [the GUI brief](lightweight-gui-zenity-alternative-brief.md); reuses its zenity-parity checklist ("What zenity actually does") instead of re-deriving it, and its finding that **zenity-rs** already occupies the "zenity without GTK" slot. Dense comparison across footprint, looks, dialog ergonomics, maintenance, and license, with primary-source citations. Written September 2026.
>
> **Sources:** GitHub releases/repos API, crates.io API, PyPI, project READMEs/docs, smenu release assets. Zenity checklist defined in the GUI brief (man.archlinux.org/man/zenity.1). Numbers I could not verify against a primary source are marked **UNVERIFIED**.

## Answer

**Top pick (use existing): gum 2.0.1 (charmbracelet, Go)** — the closest thing to a "TUI zenity" that actually exists: `gum choose/confirm/input/password/write/file/table/spin/pager` maps directly onto the message/entry/confirm/list slice of the checklist, prints the answer to stdout, exits 0/1, and has charm-grade looks (lipgloss themes, truecolor, rounded borders). Binary ships as a ~4.5–5 MB compressed Linux x86_64 tarball (uncompressed binary larger, UNVERIFIED). **The decisive gap vs zenity is the same as gum's philosophy:** it is a prompt *toolkit*, not a dialog *program* — no single `gum info "msg"` zenity-shape (you compose subcommands), no progress-from-stdin, no forms. **Runner-up: write one thin Go tool around `huh`** — charm's form library (v2.0.3, Mar 2026) gives forms/inputs/selects/notes with gum-grade styling, and bubbletea+tview-style widgets cover the rest; Go buys single-binary deployment and a mature widget ecosystem. **Top pick (Rust, build): bubbletea-clone stack doesn't exist — use `demand` 2.1.0** (jdx, MIT, active Aug 2026), a gum-inspired Rust prompt library covering input/confirm/select/multi-select/spinner — plus dialoguer/inquire as alternates. The honest Rust verdict: **no Rust prompt library reaches gum/huh's coverage**, so if Rust is mandated, a ratatui+tui-popup DIY layer is more work than the Go paths. **Baseline classics** (`dialog`/`whiptail`) still work everywhere but fail the "modern looks" requirement outright.

## Comparison table

| Candidate | Kind | Language | Footprint | Zenity checklist coverage | Modern looks | Maintenance | License |
|---|---|---|---|---|---|---|---|
| **gum** | App | Go | ~4.5 MB Linux x86_64 tar.gz (release asset; unpacked UNVERIFIED) | High for prompts: confirm/input/password/file/select-style (choose/filter/table)/write (text-info)/spin (progress-ish); no stdin-driven progress, no forms, no notification | 5/5 — lipgloss themes, truecolor, rounded, `$GUM_*` env styling | v2.0.1, 2026-09-11; very active | MIT |
| **huh** | Lib | Go | Builds into your Go binary (bubbletea runtime; Go binaries ~10–15 MB UNVERIFIED) | Forms/inputs/selects/confirm/notes — the forms gap of gum; no progress-from-stdin, no file picker | 5/5 — same charm styling family | v2.0.3, 2026-03-10; active | MIT |
| **bubbletea + lipgloss + bubbles** | Libs | Go | Go binary size (~10–15 MB UNVERIFIED) | DIY everything; bubbles has textinput/list/progress/spinner/table — most checklist parts exist as widgets | 4/5 — as good as you style it (lipgloss) | bubbletea v2 line, active 2026 (charm.land docs) | MIT |
| **demand** | Lib | Rust | Rust static binary (small, exact UNVERIFIED) | Input/password/confirm/select/multiselect/spinner/editor/DateSelect — gum-shaped API, no forms DSL, no stdin progress | 4/5 — modern themed prompts (gum-inspired) | v2.1.0, 2026-08-25 (jdx, mise author); active | MIT |
| **dialoguer** | Lib | Rust | Small | Input/password/confirm/select/multiselect/InputPrompt; no forms, no progress | 2/5 — plain `Colorize` styling, no borders/themes | 0.12.0, 2025-08-23 | MIT |
| **inquire** | Lib | Rust | Small | Input/password/confirm/select/multiselect/editor/date; no forms/progress | 3/5 — themed prompts (render config) | 0.9.4, 2026-02-24 | MIT |
| **ratatui + tui-popup + tui-realm** | Libs | Rust | Small Rust binary | DIY: popup/confirm/message widgets via tui-popup 0.7.6 or tui-realm's component/React-style framework; list/table/progress built into ratatui | 3–4/5 DIY — you own the styling | ratatui 0.30.2 (2026-06-19) very active; tui-realm 4.1.0 (2026-05-02), repo pushed 2026-07 | MIT |
| **cursive** | Lib | Rust | Small | Views incl. DialogView/ListView/EditView/Checkbox — the most dialog-shaped Rust TUI | 2/5 — ncurses-paned look, themable but dated | 0.21.1, 2024-08-03 — **stale** | MIT |
| **fzf / skim** | Apps | Go / Rust | fzf ~1–2 MB binary (UNVERIFIED) | Selection-only: replaces the `--list` slice; nothing else | 4/5 (fzf) | fzf v0.74.4 2026-09-12; skim active commit 2026-09-15 | MIT |
| **smenu** | App | C | ~200 KB musl static (release asset, verbatim) | Word-selection tool: menu/checklist-ish; not a dialog program | 2/5 | v1.5.0, 2025-05-26; steady single-maintainer | GPL-2.0 (UNVERIFIED — verify before shipping) |
| **dialog / whiptail** | Apps | C | ~100–500 KB, ncurses/newt runtime deps | Message/input/password/checklist/radiolist/menu/progressbox/gauge — the original zenity contract, text-mode | 1/5 — 1990s ncurses | Decades-stable distro packages | dialog: LGPL-2.1 (per source headers, UNVERIFIED); whiptail/newt: LGPL-2.0 (UNVERIFIED) |
| **Textual** | Lib | Python | Interpreter + app — heaviest runtime here | Widgets cover everything incl. forms; `textual-dev` CLI exists but you'd ship Python | 5/5 — CSS-based theming | 8.2.8 (PyPI, 2026), very active | MIT |
| **notcurses (+ notcurses-rs?)** | Lib | C | Heavy for this use case (multimedia/3D engine) | DIY dialogs; way overkill | 5/5 but wrong tool | Last commit 2026-05-18 (alive, sparse; "unmaintained 2024–25" reputation partially true — no release cadence, verify) | Apache-2.0 (license-change history UNVERIFIED) |

## What the zenity contract looks like in a terminal

- **Translates well:** stdout-results + exit codes are *native* to TUI prompts — this is the same contract gum/fzf/demand use (print selection, exit 0 on accept / 1 on cancel). Message/confirm/entry/password/list/checklist/progress all have terminal idioms. Forms (huh, tui-realm) and text-info-with-agree work fine.
- **Doesn't translate / DIY:**
  - **File selection** — no OS dialog; either a TUI file browser (gum `file`, demand has `FilePick`, ratatui needs a DIY browser widget) or shell out to `fzf` over a file listing.
  - **Desktop notification** — N/A in a terminal; the TUI answer is a printed spinner/line or delegating to `notify-send` (then you're back in the GUI world).
  - **Calendar/color/scale** — calendar exists in demand (`DateSelect`) and Textual; color and scale (slider) have no stock TUI idiom in any candidate here — DIY or skip.
  - **Progress from stdin** (`--progress` reading percentages) is DIY everywhere: spawn the TUI, read stdin in a thread, drive a progress/spinner widget (bubbles `progress`, ratatui gauge).
- **Structural advantage (vs the GUI brief):** TUIs have **zero display-server dependency** — no Wayland/X11 split, no portals, no GTK closure; they work over SSH, in scripts without a session bus, and cold-start is a terminal escape-sequence write, not a compositor round-trip. That kills the entire "Wayland" column of the GUI problem.

## Per-candidate notes

### gum — best existing app
- **Command surface (README):** `choose`, `filter`, `confirm`, `input`, `password`, `write`, `file`, `format`, `log`, `man`, `page`/`pager`, `spin`, `style`, `table`. Maps to checklist: confirm→confirm, entry/password→input/password, list→choose/filter/table, text-info→write, progress→`spin` (spinner-only, not percentage-driven), file→`file` (TUI file picker!). No single "message dialog" subcommand — `gum style ...` or `gum write --value` improvise. **No forms.**
- **Contract:** results on stdout, exit codes conventional (0 accept / 1 cancel) — verified pattern across charm docs/README; per-subcommand exit-code table UNVERIFIED.
- **Styling:** every subcommand has `GUM_<SUBCOMMAND>_<PART>_*` env vars; lipgloss styles (borders, padding, colors, truecolor) — this is the "modern look" bar for TUIs.
- **Footprint:** v2.0.1 release Linux x86_64 tar.gz = 4,542,686 bytes (GitHub releases API, verbatim). Uncompressed binary ~8–12 MB UNVERIFIED. Packaging: deb/rpm/apk/homebrew assets in same release.
- **License MIT** (repo). Maintenance: release 2026-09-11, charm-backed.

### demand — best Rust building block
- jdx's gum-inspired Rust prompt library (crates.io: "A CLI prompt library"): Input, Password, Confirm, Select, MultiSelect, Spin, Editor, DateSelect, FilePick. MIT, v2.1.0 (2026-08-25 release; crates.io max 2.1.0). Used in production by mise (jdx's tool). Written with its own crossterm-based event loop (pre-ratatui lineage) — not a ratatui app, which is fine for prompt-shaped dialogs.
- **Weakness:** no full-screen forms, no stdin-driven progress, smaller community than gum; aesthetic close to but not identical to gum.

### dialoguer / inquire — the Rust prompt staples
- dialoguer 0.12.0 (2025-08-23, MIT, console/crossterm underneath): the classic Input/Password/Confirm/Select/MultiSelect set; themes minimal.
- inquire 0.9.4 (2026-02-24, MIT): same shape plus editor/date, per-prompt render config. Both are **prompt libs, not dialog tools**: each call is one Q&A, no multi-field forms in one screen, no progress. Either can back the 90% checklist; forms need ratatui or a compose-of-prompts flow.

### ratatui (+ tui-popup / tui-realm) — the DIY Rust path
- ratatui 0.30.2 (2026-06-19, MIT) is the default Rust TUI engine: widgets for paragraph/table/list/gauge/canvas, crossterm backend. A zenity-shape tool = parse argv → draw one centered popup → read stdin result → exit. **tui-popup 0.7.6** (2026-06-14, "A simple popup for ratatui") covers the dialog window; **tui-realm 4.1.0** (crates.io `tuirealm`, updated 2026-05-02; repo 1002★, pushed 2026-07-29) adds a React/Elm-style component framework with ready components (input, select, checkbox, progress bar) — the fastest ratatui route to forms. Note: the old `tui-realm` hyphenated crate name 404s on crates.io; use `tuirealm`.
- Cost: you own layout, focus handling, terminal restore, and all styling — genuinely more code than any prompt-lib path, justified only if forms + progress + custom looks are all required.

### cursive — dialog-shaped but stale
- The only Rust TUI with Dialog/ListView/EditView as first-class views (i.e., the closest to "GTK dialogs in a terminal"), MIT. But last crates.io publish **2024-08-03** (0.21.1) — maintenance risk real; look is dated even when themed.

### gum-alternatives / selection-only apps
- **fzf** (Go, MIT): v0.74.4 2026-09-12, extremely active. Selection + fuzzy filter only — pairs perfectly *with* gum or as the list slice of a DIY tool.
- **skim** (Rust, MIT): fzf clone, active (commit 2026-09-15, skim-rs/skim) — the Rust-side fzf option, embeddable as a lib too.
- **smenu** (C): v1.5.0 2025-05-26, ~200 KB musl static (verified asset sizes). Powerful word-menu/checklist tool, but single-maintainer and not a dialog program.
- **Searched for "TUI zenity" and gum-likes (Sep 2026):** no maintained project bills itself as a terminal zenity; demand and gum are the two survivors of that genre. Dead/toy clones discarded (UNVERIFIED names — nothing worth citing).

### dialog / whiptail — the baseline
- `dialog` (ncurses) and `whiptail` (newt) implement the original text-mode dialog contract: msgbox/yesno/input/password/menu/checklist/radiolist/gauge (progress from stdin!) — i.e., they already cover more of the checklist than gum. Present in every distro. But visually frozen in 1995 and licenses are LGPL-family (verify exact text before bundling ideas). They are the compatibility bar any modern tool must beat on looks, not features.

### huh — the Go forms library
- charm's form library: fields for input, text, select, multiselect, confirm, notes — with groups and validation. v2.0.3 (2026-03-10). If you build a zenity-shape tool in Go, **huh covers the forms slice gum lacks, and gum-style styling comes free** via lipgloss/huh themes. The gum-vs-huh split for a *builder*: gum = composable one-shots from shell, huh = programmatic multi-field dialogs. A Go zenity would be: argv → map to huh form or single field → print result → exit; ~a weekend of work (estimate UNVERIFIED).

### Textual / notcurses / ncurses — honorable mentions
- **Textual 8.2.8** (PyPI, MIT): the best-looking TUI framework anywhere (CSS theming, every widget incl. forms) — but you ship Python and its runtime; honest weight verdict: fine for a personal tool, wrong for a light single binary.
- **notcurses** (C, Apache-2.0): spectacular rendering (images, video, 3D) and last commit 2026-05-18 — alive but sparse, and rumor of unmaintenance in 2024–25 is not fully refuted (no release cadence; release history UNVERIFIED). Massively overkill for dialogs; Rust bindings (notcurses-rs) activity UNVERIFIED. Skip.
- **ncurses**: the baseline runtime under `dialog`; GPL-2.0-ish library economics fine for a GPL project, but you'd be rebuilding whiptail. Skip.

## Recommendation

1. **Use existing: gum 2.0.1.** If the need is "modern-looking prompts from shell scripts," gum is a maintained, MIT, charm-backed TUI zenity for the 80% case (confirm/input/password/choose/file/write), and pairs with `fzf` for fancy selection. Gap vs zenity: no forms, no stdin progress, no single message-dialog command. Zero build cost.
2. **Build in Go: bubbletea + huh (+ lipgloss).** Full checklist reachability (forms via huh, progress via bubbles, file list via `file`/fzf embeds), gum-grade looks, single binary. This is the lowest-effort *complete-parity* path.
3. **Build in Rust: demand 2.1.0 for prompt coverage; ratatui + tui-popup (+ tuirealm) only if forms/stdin-progress/custom styling are hard requirements.** Rust's prompt-lib layer (demand/dialoguer/inquire) does not reach gum/huh parity, and cursive — the one dialog-shaped Rust TUI — is stale since 2024. Expect the ratatui DIY route to cost more than the Go route for the same result.
4. **Baseline:** `dialog`/`whiptail` remain the feature-per-byte kings and prove the stdout/exit-code contract works in pure terminal; any new tool justifies itself purely on looks + ergonomics.
5. **Cross-reference:** the GUI brief's zenity-rs already covers "zenity without GTK" in GUI space; a TUI tool's differentiation is scripts-running-over-SSH/headless and instant cold start — not raw feature parity.

## Sources

- gum v2.0.1 release (2026-09-11) + asset sizes — https://api.github.com/repos/charmbracelet/gum/releases/latest ; README/command surface — https://github.com/charmbracelet/gum
- huh v2.0.3 (2026-03-10) — https://api.github.com/repos/charmbracelet/huh/releases/latest ; docs — https://charm.land/huh/
- fzf v0.74.4 (2026-09-12) — https://api.github.com/repos/junegunn/fzf/releases/latest
- skim activity (commit 2026-09-15) — https://github.com/skim-rs/skim
- smenu v1.5.0 (2025-05-26), asset sizes — https://api.github.com/repos/p-gen/smenu/releases/latest
- demand — https://crates.io/api/v1/crates/demand (max 2.1.0, MIT) ; release v2.1.0 2026-08-25 — https://github.com/jdx/demand/releases/tag/v2.1.0
- dialoguer — https://crates.io/api/v1/crates/dialoguer (0.12.0, 2025-08-23, MIT)
- inquire — https://crates.io/api/v1/crates/inquire (0.9.4, 2026-02-24, MIT)
- ratatui — https://crates.io/api/v1/crates/ratatui (0.30.2, 2026-06-19, MIT)
- tui-popup — https://crates.io/api/v1/crates/tui-popup (0.7.6, 2026-06-14)
- tui-realm — repo https://github.com/veeso/tui-realm (pushed 2026-07-29, MIT); crate `tuirealm` — https://crates.io/api/v1/crates/tuirealm (4.1.0, 2026-05-02)
- cursive — https://crates.io/api/v1/crates/cursive (0.21.1, 2024-08-03, MIT)
- Textual — https://pypi.org/pypi/textual/json (8.2.8, MIT)
- notcurses last commit 2026-05-18 — https://api.github.com/repos/dankamongmen/notcurses/commits?per_page=1
- tview (Go, reference) v0.42.0 2025-08-27, commit 2026-08-11 — https://github.com/rivo/tview
- Zenity parity checklist: see sibling GUI brief §"What zenity actually does" (man.archlinux.org/man/zenity.1)
