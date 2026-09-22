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
--            driver)
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
-- none of them is in the pool yet, so this package cannot RUN
-- containers until they land as ports:
--
--   crun (or runc)    OCI runtime; crun-first lookup
--                     (config.findRuntime)
--   conmon            container monitor; PATH lookup
--   pasta             rootless network default + rootless port
--                     forwarder (podman 5/6 default, replacing
--                     slirp4netns)
--   netavark          bridge network stack (rootful; rootless
--                     opt-in)
--   aardvark-dns      DNS on netavark bridges
--   catatonit         --init binary (config.FindInitBinary)
--   fuse-overlayfs    rootless overlay fallback (native-overlay
--                     kernels do not need it)
--   containers-common /etc/containers config; policy.json is
--                     ErrorIfNotFound in containers/image — image
--                     pulls fail without it
--
-- plus the dropped-tag libraries: a future libseccomp port re-enables
-- seccomp profile enforcement (BUILDTAGS += seccomp), libsystemd the
-- journald log driver, libsubid NSS subuid lookup (until then podman
-- falls back to /etc/subuid parsing), libapparmor apparmor profile
-- loading.
--
-- Requires: glibc; crun, conmon, pasta, netavark, aardvark-dns,
-- catatonit, fuse-overlayfs, containers-common (all not yet in pool —
-- see KNOWN GAPS). build_deps: go (vendored build), toolchain (CGO
-- compiler for the sqlite amalgamation).

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
            for the SQLite state database. NOTE: the container-runtime
            helper family (crun, conmon, pasta, netavark,
            aardvark-dns, catatonit, fuse-overlayfs,
            containers-common) is not yet in the pool — see the port
            header before relying on container execution.
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
            "mkdir -p $STAGE/usr/bin",
            "export HOME=/tmp GOCACHE=/tmp/shuttle-go-gocache GOPATH=/tmp/shuttle-go-gopath",
            'export GOFLAGS="-trimpath -mod=vendor" GOPROXY=off GOWORK=off GOTOOLCHAIN=local',
            'cd $SRC && CGO_ENABLED=1 go build -ldflags "-X go.podman.io/podman/v6/libpod/config._installPrefix=/usr -X go.podman.io/podman/v6/libpod/config._etcDir=/etc -X go.podman.io/podman/v6/pkg/systemd/quadlet._binDir=/usr/bin" -tags "grpcnotrace exclude_graphdriver_btrfs" -o $STAGE/usr/bin/podman ./cmd/podman',
        }, " && "),

        type = "source",
        requires = {
            "glibc",
            "crun",
            "conmon",
            "pasta",
            "netavark",
            "aardvark-dns",
            "catatonit",
            "fuse-overlayfs",
            "containers-common",
        },
        build_deps = { "go", "toolchain" },

        apps = {
            podman = app {
                command = "usr/bin/podman",
                plugs = { "home", "network", "network-bind" },
            },
        },
    },
}
