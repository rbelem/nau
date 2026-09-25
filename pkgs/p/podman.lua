-- podman: daemonless container engine — run OCI containers and pods
-- without a root daemon (podman-container-tools/podman v6.1.2,
-- released 2026-09-16; GitHub's latest stable tag — a security fix
-- release over the 6.1 line).
-- https://github.com/podman-container-tools/podman (the repo moved
-- from containers/podman; both orgs serve byte-identical tag
-- tarballs — cross-checked by sha256)
--
-- Three-way comparison:
--
-- Nix:       pkgs.podman (buildGoModule over the tag tree; seccomp/
--            systemd/btrfs tags per pkg-config probes)
-- Snapcraft: no upstream snapcraft recipe in the podman repo
-- Shuttle:   declarative Lua — vendored Go source build via the pool
--            go toolchain. NO services declaration: podman is
--            daemonless — there is nothing to run; `podman system
--            service` is an on-demand invocation, not a v1 service
--            shape.
--
-- Port strategy: the release tarball vendors the complete Go module
-- closure (vendor/ + modules.txt), so the build is fully offline —
-- -mod=vendor with GOPROXY=off and no deps.go resolver (the
-- gojq/bifrost proxy fetch is unneeded). The build command mirrors
-- the Makefile's bin/podman recipe verbatim (go build ./cmd/podman,
-- GOFLAGS -trimpath, LDFLAGS_PODMAN), with BUILDTAGS resolved by hand
-- for the pool instead of the hack/*.sh pkg-config probes:
--
--   kept:    grpcnotrace (upstream default), exclude_graphdriver_btrfs
--            (no btrfs headers in the pool; overlay is the storage
--            driver), seccomp (issue #215: the #21-era build shipped
--            WITHOUT it and every default `podman run` died at spec
--            generation — common/pkg/seccomp/seccomp_unsupported.go
--            errNotSupported; the pool libseccomp port supplies the
--            cgo pkg-config: libseccomp probe)
--   dropped: apparmor/btrfs/sqlite/systemd/libsubid probes (their
--            hack/*.tag.sh autodetects have no pool counterpart and
--            no-op cleanly; libsubid falls back to /etc/subuid file
--            parsing, functionally identical for rootless userns)
--   added:   none needed for gpgme — the !openpgp path
--            (mechanism_gpgme_only.go) is pure Go, no cgo gpgme
--   dropped: seccomp, systemd, libsubid, apparmor, libsqlite3 — each
--            probe needs a system library the pool lacks. None blocks
--            the build; each narrows behavior (see KNOWN GAPS).
--
-- CGO is REQUIRED, not optional: libpod's state database is SQLite
-- through github.com/mattn/go-sqlite3, which compiles its bundled
-- amalgamation with the C compiler (CGO_ENABLED=1 + the pool
-- toolchain build_dep — the bifrost shape). A CGO_ENABLED=0 build
-- "can never actually talk to SQLite at runtime"
-- (libpod/sqlite_constraint_nocgo.go — it exists only for CGO-free
-- static analysis). go-sqlite3 WITHOUT the libsqlite3 tag builds the
-- vendored amalgamation, so no system sqlite3 is needed.
--
-- ldflags pin the upstream install layout (PREFIX=/usr, the
-- Makefile's RELEASE_PREFIX used by distro packagers):
-- config._installPrefix, config._etcDir, quadlet._binDir. gitCommit/
-- buildInfo are $(if ...)-guarded -X in the Makefile and stay empty
-- in tarball builds — omitted; the version itself is baked into
-- source (version/rawversion.RawVersion).
--
-- Sibling upstream binaries NOT staged (each is a separate make
-- target): quadlet (systemd generator; LIBEXECDIR layout the pool has
-- not grown yet) and rootlessport (the slirp4netns port-forward
-- child; podman 6's rootless default is pasta, which does not use
-- it). Follow-ups if a consumer needs them. Man pages and shell
-- completions are skipped (go-md2man not in the pool; cosmetic).
--
-- KNOWN GAPS (declared, not resolved): podman is a runtime
-- ORCHESTRATOR — it execs its helpers by name at container time, and
-- Runtime helper family, pool status after #215:
--
--   crun 1.30.1          IN POOL (prebuilt release fetch)
--   conmon 2.2.1         IN POOL (prebuilt release fetch)
--   passt g21550f5       IN POOL (prebuilt release fetch; pasta is
--                        podman 5/6's rootless network default)
--   fuse-overlayfs 1.18  IN POOL (prebuilt release fetch; rootless
--                        overlay fallback — native-overlay kernels,
--                        5.13+, do not need it)
--   libseccomp 2.6.1     IN POOL (source port; required by the
--                        seccomp BUILDTAG, see the kept/dropped
--                        block above)
--
-- Still NOT in the pool, and NOT in requires because the default
-- rootless run path never execs them:
--
--   netavark / aardvark-dns   bridge-network stack (rootless default
--                             is pasta); needed only for custom
--                             bridge networks and `podman build`
--                             with --network=bridge
--   catatonit                 only exec'd for --init containers
--
-- Config: the payload ships the upstream minimal default
-- /usr/share/containers/policy.json (insecureAcceptAnything — the
-- common distro default; image pulls ErrorIfNotFound without it,
-- containers/image signature policy). The pod shell sees the HOST
-- /usr (NixOS: no /usr/share/containers), so the pull path is wired
-- via CONTAINERS_POLICY_JSON pointing at the pod tree's copy — a
-- machine-specific literal in the daily pod declaration
-- (<podroot>/active/extensions/podman/usr/share/containers/
-- policy.json; `active` is generation-stable). Storage needs NO conf:
-- the rootless defaults (graphroot ~/.local/share/containers/storage,
-- runroot $XDG_RUNTIME_DIR/containers, containers/storage
-- types/options.go setDefaultRootlessStoreOptions) are exactly the
-- ticket's target.
--
-- Requires: glibc + the helper family above + libseccomp (podman's
-- DT_NEEDED set: libc, libseccomp.so.2 — resolved by name through the
-- #10 loader-lib machinery). build_deps: go (vendored build),
-- toolchain (CGO compiler for the sqlite amalgamation + the seccomp
-- binding), pkg-config (the `#cgo pkg-config: libseccomp` probe),
-- libseccomp (headers + shared lib in the merged prefix).

return {
    default = snap {
        name = "podman",
        version = "6.1.2",
        summary = "Daemonless container engine for OCI containers and pods",
        description = [[
            Podman runs, builds, and manages OCI containers and pods
            with a daemonless, rootless-first architecture and a
            Docker-compatible CLI. Built from the vendored v6.1.2
            release tree with the pool Go toolchain; CGO is required
            for the SQLite state database. The rootless
            helper family (crun, conmon, pasta,
            fuse-overlayfs, libseccomp) ships in the pool;
            bridge networking (netavark, aardvark-dns) and
            --init (catatonit) remain outside requires —
            see the port header before relying on those
            paths.
        ]],
        license = "Apache-2.0",
        grade = "stable",
        confinement = "strict",
        architectures = { "amd64" },

        source = {
            url = "https://github.com/podman-container-tools/podman/archive/refs/tags/v6.1.2.tar.gz",
            sha256 = "a4b2b10bd560cf9b4c50c282bd04bb74486ff6c78bebd51427f779fe985fc1bb",
        },

        -- Hermetic vendored build: GOTOOLCHAIN=local and GOPROXY=off
        -- make the no-network property explicit (-mod=vendor would be
        -- the default with a vendor/ tree present; go.mod wants go
        -- >= 1.26.0 and the pool go 1.27.1 satisfies it locally).
        -- Caches live under /tmp (zenity HOME / bifrost GOPATH
        -- precedent — the sandbox home is not writable). The final
        -- command is the Makefile's bin/podman recipe with the
        -- pool-resolved BUILDTAGS documented in the header.
        build = table.concat({
            "mkdir -p $STAGE/usr/bin $STAGE/usr/share/containers",
            "export HOME=/tmp GOCACHE=/tmp/shuttle-go-gocache GOPATH=/tmp/shuttle-go-gopath",
            'export GOFLAGS="-trimpath -mod=vendor" GOPROXY=off GOWORK=off GOTOOLCHAIN=local',
            'cd $SRC && CGO_ENABLED=1 go build -ldflags "-X go.podman.io/podman/v6/libpod/config._installPrefix=/usr -X go.podman.io/podman/v6/libpod/config._etcDir=/etc -X go.podman.io/podman/v6/pkg/systemd/quadlet._binDir=/usr/bin" -tags "grpcnotrace exclude_graphdriver_btrfs seccomp" -o $STAGE/usr/bin/podman ./cmd/podman',
            -- The upstream minimal default signature policy (the
            -- common distro default): image pulls are
            -- ErrorIfNotFound in containers/image, and the pod shell's
            -- /usr is the host's — the pod wires CONTAINERS_POLICY_JSON
            -- at this file (see header).
            'printf \'%s\\n\' \'{"default":[{"type":"insecureAcceptAnything"}]}\' > $STAGE/usr/share/containers/policy.json',
        }, " && "),

        type = "source",
        requires = {
            "glibc",
            "crun",
            "conmon",
            "pasta",
            "fuse-overlayfs",
            "libseccomp",
        },
        build_deps = { "go", "toolchain", "pkg-config", "libseccomp" },

        apps = {
            podman = app {
                command = "usr/bin/podman",
                plugs = { "home", "network", "network-bind" },
            },
        },
    },
}
