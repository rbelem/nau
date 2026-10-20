-- The gcc payload's launch shims: the `cc`/`c++` driver shim and the
-- binutils tool shims.
--
-- Split out of pkgs/g/gcc.lua (the recipe is past the repo's token
-- budget) because the two shim families share ONE block — the dynamic
-- loader search — and keeping it in the recipe meant fixing it twice.
--
-- Usage:
--   local shims = require("lib/gcc_shims")
--   build = table.concat({ ..., shims.cc, shims.binutils, ... }, " && ")

local M = {}

-- The dynamic loader that matches the libc on the loader path.
--
-- glibc 2.44's libc.so.6 references __pointer_chk_guard as
-- UND@GLIBC_PRIVATE: the symbol moved into the dynamic loader, so only
-- a matching 2.44 loader can satisfy it. A binary started by a foreign
-- loader dies with "symbol lookup error: .../libc.so.6: undefined
-- symbol: __pointer_chk_guard, version GLIBC_PRIVATE" — measured
-- 2026-10-19 with nixpkgs' own glibc 2.44 AND with a source-built 2.44,
-- so it is a glibc-2.44 property, not a payload defect.
--
-- The loader ships beside the libc it matches, so the pair is what the
-- search looks for; a pod with no glibc extension finds none and the
-- binary starts normally.
--
-- Since the pod rootfs landed (crates/nau-pod/src/rootfs.rs) this is a
-- FALLBACK, not the primary mechanism. The farm wrapper and the pod's
-- systemd units enter a mount namespace in which the pod's loader
-- answers /lib64/ld-linux-x86-64.so.2, so the kernel starts the driver
-- AND its children on the matching loader. The search stays for
-- contexts with no namespace: a directly invoked payload tool with the
-- pair on LD_LIBRARY_PATH. In the build sandbox the prefix's loader
-- list omits the root slibdir (crates/nau-build/src/prefix_paths.rs),
-- so it finds nothing and execs directly, exactly as before.
local LOADER_SEARCH = [[
ld=
ifs=\$IFS; IFS=:
for p in \$LD_LIBRARY_PATH; do
  [ -n "\$p" ] && [ -x "\$p/ld-linux-x86-64.so.2" ] && [ -e "\$p/libc.so.6" ] && { ld="\$p/ld-linux-x86-64.so.2"; break; }
done
IFS=\$ifs
]]

-- cc/c++ shims: the farm LD wrapper exports the pod's lib dirs as
-- LIBRARY_PATH, which the driver honors for its OWN file search
-- (startfiles, static libs) but does NOT forward to the linker as -L.
-- rustc links via rust-lld (-fuse-ld=lld), whose defaults are the HOST
-- root — dynamic -lc/-lm/-lstdc++ would resolve against the host, not
-- the payload (issue #164). The shims translate LIBRARY_PATH into -L so
-- every link searches the pod's payload dirs, and dispatch on the
-- invoked name: c++/g++/cxx hit the C++ driver (C++ link spec),
-- everything else the C driver.
--
-- CPATH is translated to -idirafter, never left at -I position:
-- libstdc++'s cstdlib pulls the C stdlib.h via #include_next, which
-- only searches dirs AFTER the C++ headers — glibc's include root
-- entering at -I position is unreachable by include_next and every C++
-- TU dies on `stdlib.h: No such file or directory` (the gen-39 shim
-- carried this loop; the #171 triplet parameterization dropped it and
-- the gate cargo build caught it).
--
-- Empty segments (leading/trailing colon) are skipped: a bare `-L` is
-- an ld operator that consumes the NEXT token, not a no-op. The
-- heredoc is UNQUOTED: $t is the build's triplet (expanded at authoring
-- time, so the shim carries the literal driver names); \$d/\$l/... stay
-- runtime vars.
M.cc = [[cat > "$STAGE/usr/bin/cc" <<EOF
#!/bin/sh
d=\$(dirname "\$(readlink -f "\$0")")
l=
c=
ifs=\$IFS; IFS=:
for p in \$LIBRARY_PATH; do [ -n "\$p" ] && l="\$l -L\$p"; done
for p in \$CPATH; do [ -n "\$p" ] && c="\$c -idirafter \$p"; done
IFS=\$ifs]] .. LOADER_SEARCH .. [[
case "\${0##*/}" in
  c++|cxx|g++)
    if [ -n "\$ld" ]; then exec "\$ld" --library-path "\$LD_LIBRARY_PATH" "\$d/$t-g++-16" \$l \$c "\$@"; fi
    exec "\$d/$t-g++-16" \$l \$c "\$@" ;;
  *)
    if [ -n "\$ld" ]; then exec "\$ld" --library-path "\$LD_LIBRARY_PATH" "\$d/$t-gcc-16" \$l \$c "\$@"; fi
    exec "\$d/$t-gcc-16" \$l \$c "\$@" ;;
esac
EOF
chmod +x "$STAGE/usr/bin/cc" && cp "$STAGE/usr/bin/cc" "$STAGE/usr/bin/c++"]]

-- binutils tool shims: the deb set's plain /usr/bin/ar, as, ld, ... are
-- relative symlinks to triplet binaries whose DT_NEEDED (libbfd,
-- libopcodes, ...) live in the payload's multiarch lib dir. A pod run
-- has the farm LD wrapper to supply it; a MERGED BUILD PREFIX
-- (build_deps consumer, ADR-0018) has no such wrapper — libtool's
-- first `ar` call died loading libbfd (#171 gap-3 proof). Each shim
-- self-locates via readlink -f (works in stage, store blob and
-- extension layouts alike), prepends its own payload's multiarch dir to
-- LD_LIBRARY_PATH (never clobbering an existing one), and execs the
-- triplet binary named after its own invoked name. Authored per arch
-- ($t bakes the triplet; everything \$-escaped stays a runtime
-- variable).
M.binutils = [[for x in ar as ld nm ranlib strip objcopy objdump readelf strings size addr2line; do
  rm -f "$STAGE/usr/bin/$x"
  cat > "$STAGE/usr/bin/$x" <<EOF
#!/bin/sh
d=\$(dirname "\$(readlink -f "\$0")")
n=\${0##*/}
LD_LIBRARY_PATH="\$d/../lib/$t\${LD_LIBRARY_PATH:+:\$LD_LIBRARY_PATH}"
export LD_LIBRARY_PATH]] .. LOADER_SEARCH .. [[
if [ -n "\$ld" ]; then
  exec "\$ld" --library-path "\$LD_LIBRARY_PATH" "\$d/$t-\$n" "\$@"
fi
exec "\$d/$t-\$n" "\$@"
EOF
  chmod +x "$STAGE/usr/bin/$x" || exit 1
done]]

return M
