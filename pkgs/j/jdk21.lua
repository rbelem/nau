-- jdk21: Eclipse Temurin 21 LTS JDK — the Java development kit as a
-- prebuilt binary port (Adoptium jdk-21.0.12.1+1, the 21.0.12.1
-- security-update build over the 21.0.12 line, JAVA_VERSION_DATE
-- 2026-08-18; Adoptium API latest-GA for
-- version=[21],x64/linux/jdk/hotspot resolved 2026-09-20).
-- https://github.com/adoptium/temurin21-binaries (the GitHub release
-- the api.adoptium.net asset links point into).
--
-- Issue #21 owner direction: per-version JVM PODS — a jdk21 pod, a
-- jdk17 pod, … — each pod declaring exactly one JDK version, instead
-- of one mutable global default (the sdkman model shuttle absorbs
-- selectively). A JDK source build is out of scope (multi-hour
-- bootstrap); this port vendors the upstream Temurin binary tarball,
-- which is redistributable.
--
-- sdkman absorption (issue #21 steal-list), mapped onto shuttle:
--
--   .sdkmanrc per-project pins  →  the per-project pod: a project
--     pod declares jdk21 (or jdk17, as its own port) and nothing
--     else mutates a global state
--   `sdk home`                  →  the store-path query for
--     script-safe JAVA_HOME: `shuttle pod shellenv --json` serves
--     the generation's recorded env (`vars`), so
--     `JAVA_HOME=$(shuttle pod shellenv --json | jq -r .vars.JAVA_HOME)`
--     never parses shell text; `shuttle run --pod jdk21 -- ./mvnw`
--     overlays the same map onto the exec'd process
--   vendor suffix variants      →  sibling ports, not a variant
--     knob: jdk21 (this port, Temurin), future jdk21-zulu /
--     jdk21-corretto follow the same shape with their own pins
--
-- sdkman pieces NOT stolen (issue #21): the download network broker,
-- imperative global state (the `sdk default`/`sdk current` mutable
-- symlinks — shuttle's generation chain is the substitute), and
-- shell auto-env hooks (.sdkmanrc auto-switching on cd — activation
-- stays opt-in `eval "$(shuttle pod shellenv)"`, never an ambient
-- hook that rewrites env behind the shell's back).
--
-- License class: Temurin builds are GPLv2 with the Classpath
-- Exception (GPL-2.0-only WITH Classpath-exception-2.0) — the
-- redistributable class; the tree ships under legal/ and is staged
-- whole. Oracle JDK (OTN license, NOT redistributable) is never a
-- port candidate — the vendor-variant idea above applies to
-- GPLv2+CE / similarly redistributable builds only.
--
-- Port strategy — the go.lua relayout, at JDK-home scale: the
-- tarball's single top-level dir is the JDK home; the build stages
-- it WHOLE at the prefix root ($STAGE/usr) — bin/, conf/, include/,
-- jmods/, legal/, lib/, man/, NOTICE, release — because JDK
-- launchers resolve their home relative to /proc/self/exe and an
-- only-bin staging would strand lib/modules. `usr/bin` therefore
-- carries the real launcher set, which also puts `javac`/`java` on
-- the merged build prefix PATH for build_deps consumers (the
-- go.lua dual-use note).
--
-- Farm apps — every bin/ tool, via JDK-HOME-ROOT launchers: the
-- issue #37 assembly captures only the command binary's directory,
-- so a farm command at usr/bin/java would assemble bin/ alone and
-- strand lib/modules (go.lua issue #46 gap verbatim, at 29x
-- scale). Each tool gets a two-line sh launcher AT usr/<tool>
-- (exec $(dirname $0)/bin/<tool>) so the assembly root is the
-- prefix: the whole JDK hardlinks beside every app (hardlinks, not
-- copies — one store blob set serves all 29 assemblies).
--
-- JAVA_HOME is NOT hardcoded here — a port cannot know which pod
-- will host it. The jdk21-pod declares it per ADR-0030 (generation-
-- scoped `env = { … }`, literal UTF-8 values, no farm/generation
-- interpolation; PATH/LD_LIBRARY_PATH rejected as reserved seams —
-- the src/pod.rs parse tests pin that shape:
-- `pod { packages = { "jq" }, env = { EDITOR = "vi" } }`). The
-- declaration stays generation-stable through the `current` flip
-- because the assembled tree is addressable as
-- `<pod-root>/current/../apps/jdk21/usr` (current →
-- generations/<n>/farm, so the flip alone re-scopes JAVA_HOME).
--
-- KNOWN GAPS (declared, not resolved): man pages stage at usr/man
-- (not usr/share/man — the pool prefix is not FHS-complete);
-- jconsole's GUI needs host X11 libs at runtime (same as any
-- distro JDK, not a port gap); no ca-certificates wiring —
-- Temurin bundles its own cacerts and trusts the JDK store, host
-- CA stores are not consulted (documented behavior, matches
-- upstream).
--
-- Requires: glibc (java and libjvm.so DT_NEEDED resolve to the
-- glibc family only — libpthread/libdl/libm/librt — everything
-- else is $ORIGIN-relative; verified on the pinned build).
-- build_deps: none — a binary relayout, no compilation.

return {
    default = snap {
        name = "jdk21",
        version = "21.0.12.1+1",
        summary = "Temurin 21 LTS JDK — binary build for per-version JVM pods",
        description = [[
            Eclipse Temurin 21 LTS (jdk-21.0.12.1+1): the full JDK —
            java, javac, jshell, jlink, jpackage and the complete
            bin/ tool set — staged from the upstream binary tarball.
            Designed for the per-version JVM pod model: declare this
            package in a dedicated pod; the pod declares JAVA_HOME
            (ADR-0030 env); `shuttle pod shellenv --json` is the
            script-safe store-path query. GPLv2 + Classpath
            Exception (redistributable).
        ]],
        license = "GPL-2.0-only WITH Classpath-exception-2.0",
        grade = "stable",
        confinement = "strict",
        architectures = { "amd64" },

        source = {
            url = "https://github.com/adoptium/temurin21-binaries/releases/download/jdk-21.0.12.1%2B1/OpenJDK21U-jdk_x64_linux_hotspot_21.0.12.1_1.tar.gz",
            sha256 = "ce79869e1307ed8ee1e2baa86a412b1eb5b75d10a01006d788a6f968bcfaee94",
        },

        -- $SRC is the extracted JDK home (the harness flattens the
        -- tarball's single top-level dir). Stage it whole at the
        -- prefix root, then write one JDK-home-root launcher per
        -- tool — the go.lua wrapper shape: readlink -f resolves $0
        -- through the farm symlink chain before deriving the home,
        -- three single-substitution lines (no nesting) so the
        -- preflight PATH probe does not mis-split them.
        build = table.concat({
            "mkdir -p $STAGE/usr",
            "cp -a bin conf include jmods legal lib man NOTICE release $STAGE/usr/",
            "printf '%s\\n' '#!/bin/sh' 'p=$(readlink -f -- \"$0\")' 'd=$(dirname -- \"$p\")' 'exec \"$d/bin/jar\" \"$@\"' > $STAGE/usr/jar",
            "printf '%s\\n' '#!/bin/sh' 'p=$(readlink -f -- \"$0\")' 'd=$(dirname -- \"$p\")' 'exec \"$d/bin/jarsigner\" \"$@\"' > $STAGE/usr/jarsigner",
            "printf '%s\\n' '#!/bin/sh' 'p=$(readlink -f -- \"$0\")' 'd=$(dirname -- \"$p\")' 'exec \"$d/bin/java\" \"$@\"' > $STAGE/usr/java",
            "printf '%s\\n' '#!/bin/sh' 'p=$(readlink -f -- \"$0\")' 'd=$(dirname -- \"$p\")' 'exec \"$d/bin/javac\" \"$@\"' > $STAGE/usr/javac",
            "printf '%s\\n' '#!/bin/sh' 'p=$(readlink -f -- \"$0\")' 'd=$(dirname -- \"$p\")' 'exec \"$d/bin/javadoc\" \"$@\"' > $STAGE/usr/javadoc",
            "printf '%s\\n' '#!/bin/sh' 'p=$(readlink -f -- \"$0\")' 'd=$(dirname -- \"$p\")' 'exec \"$d/bin/javap\" \"$@\"' > $STAGE/usr/javap",
            "printf '%s\\n' '#!/bin/sh' 'p=$(readlink -f -- \"$0\")' 'd=$(dirname -- \"$p\")' 'exec \"$d/bin/jcmd\" \"$@\"' > $STAGE/usr/jcmd",
            "printf '%s\\n' '#!/bin/sh' 'p=$(readlink -f -- \"$0\")' 'd=$(dirname -- \"$p\")' 'exec \"$d/bin/jconsole\" \"$@\"' > $STAGE/usr/jconsole",
            "printf '%s\\n' '#!/bin/sh' 'p=$(readlink -f -- \"$0\")' 'd=$(dirname -- \"$p\")' 'exec \"$d/bin/jdb\" \"$@\"' > $STAGE/usr/jdb",
            "printf '%s\\n' '#!/bin/sh' 'p=$(readlink -f -- \"$0\")' 'd=$(dirname -- \"$p\")' 'exec \"$d/bin/jdeprscan\" \"$@\"' > $STAGE/usr/jdeprscan",
            "printf '%s\\n' '#!/bin/sh' 'p=$(readlink -f -- \"$0\")' 'd=$(dirname -- \"$p\")' 'exec \"$d/bin/jdeps\" \"$@\"' > $STAGE/usr/jdeps",
            "printf '%s\\n' '#!/bin/sh' 'p=$(readlink -f -- \"$0\")' 'd=$(dirname -- \"$p\")' 'exec \"$d/bin/jfr\" \"$@\"' > $STAGE/usr/jfr",
            "printf '%s\\n' '#!/bin/sh' 'p=$(readlink -f -- \"$0\")' 'd=$(dirname -- \"$p\")' 'exec \"$d/bin/jhsdb\" \"$@\"' > $STAGE/usr/jhsdb",
            "printf '%s\\n' '#!/bin/sh' 'p=$(readlink -f -- \"$0\")' 'd=$(dirname -- \"$p\")' 'exec \"$d/bin/jimage\" \"$@\"' > $STAGE/usr/jimage",
            "printf '%s\\n' '#!/bin/sh' 'p=$(readlink -f -- \"$0\")' 'd=$(dirname -- \"$p\")' 'exec \"$d/bin/jinfo\" \"$@\"' > $STAGE/usr/jinfo",
            "printf '%s\\n' '#!/bin/sh' 'p=$(readlink -f -- \"$0\")' 'd=$(dirname -- \"$p\")' 'exec \"$d/bin/jlink\" \"$@\"' > $STAGE/usr/jlink",
            "printf '%s\\n' '#!/bin/sh' 'p=$(readlink -f -- \"$0\")' 'd=$(dirname -- \"$p\")' 'exec \"$d/bin/jmap\" \"$@\"' > $STAGE/usr/jmap",
            "printf '%s\\n' '#!/bin/sh' 'p=$(readlink -f -- \"$0\")' 'd=$(dirname -- \"$p\")' 'exec \"$d/bin/jmod\" \"$@\"' > $STAGE/usr/jmod",
            "printf '%s\\n' '#!/bin/sh' 'p=$(readlink -f -- \"$0\")' 'd=$(dirname -- \"$p\")' 'exec \"$d/bin/jpackage\" \"$@\"' > $STAGE/usr/jpackage",
            "printf '%s\\n' '#!/bin/sh' 'p=$(readlink -f -- \"$0\")' 'd=$(dirname -- \"$p\")' 'exec \"$d/bin/jps\" \"$@\"' > $STAGE/usr/jps",
            "printf '%s\\n' '#!/bin/sh' 'p=$(readlink -f -- \"$0\")' 'd=$(dirname -- \"$p\")' 'exec \"$d/bin/jrunscript\" \"$@\"' > $STAGE/usr/jrunscript",
            "printf '%s\\n' '#!/bin/sh' 'p=$(readlink -f -- \"$0\")' 'd=$(dirname -- \"$p\")' 'exec \"$d/bin/jshell\" \"$@\"' > $STAGE/usr/jshell",
            "printf '%s\\n' '#!/bin/sh' 'p=$(readlink -f -- \"$0\")' 'd=$(dirname -- \"$p\")' 'exec \"$d/bin/jstack\" \"$@\"' > $STAGE/usr/jstack",
            "printf '%s\\n' '#!/bin/sh' 'p=$(readlink -f -- \"$0\")' 'd=$(dirname -- \"$p\")' 'exec \"$d/bin/jstat\" \"$@\"' > $STAGE/usr/jstat",
            "printf '%s\\n' '#!/bin/sh' 'p=$(readlink -f -- \"$0\")' 'd=$(dirname -- \"$p\")' 'exec \"$d/bin/jstatd\" \"$@\"' > $STAGE/usr/jstatd",
            "printf '%s\\n' '#!/bin/sh' 'p=$(readlink -f -- \"$0\")' 'd=$(dirname -- \"$p\")' 'exec \"$d/bin/jwebserver\" \"$@\"' > $STAGE/usr/jwebserver",
            "printf '%s\\n' '#!/bin/sh' 'p=$(readlink -f -- \"$0\")' 'd=$(dirname -- \"$p\")' 'exec \"$d/bin/keytool\" \"$@\"' > $STAGE/usr/keytool",
            "printf '%s\\n' '#!/bin/sh' 'p=$(readlink -f -- \"$0\")' 'd=$(dirname -- \"$p\")' 'exec \"$d/bin/rmiregistry\" \"$@\"' > $STAGE/usr/rmiregistry",
            "printf '%s\\n' '#!/bin/sh' 'p=$(readlink -f -- \"$0\")' 'd=$(dirname -- \"$p\")' 'exec \"$d/bin/serialver\" \"$@\"' > $STAGE/usr/serialver",
            "chmod +x $STAGE/usr/jar $STAGE/usr/jarsigner $STAGE/usr/java $STAGE/usr/javac $STAGE/usr/javadoc $STAGE/usr/javap $STAGE/usr/jcmd $STAGE/usr/jconsole $STAGE/usr/jdb $STAGE/usr/jdeprscan $STAGE/usr/jdeps $STAGE/usr/jfr $STAGE/usr/jhsdb $STAGE/usr/jimage $STAGE/usr/jinfo $STAGE/usr/jlink $STAGE/usr/jmap $STAGE/usr/jmod $STAGE/usr/jpackage $STAGE/usr/jps $STAGE/usr/jrunscript $STAGE/usr/jshell $STAGE/usr/jstack $STAGE/usr/jstat $STAGE/usr/jstatd $STAGE/usr/jwebserver $STAGE/usr/keytool $STAGE/usr/rmiregistry $STAGE/usr/serialver",
        }, " && "),

        type = "source",
        requires = { "glibc" },

        apps = {
            jar = app { command = "usr/jar" },
            jarsigner = app { command = "usr/jarsigner" },
            java = app { command = "usr/java" },
            javac = app { command = "usr/javac" },
            javadoc = app { command = "usr/javadoc" },
            javap = app { command = "usr/javap" },
            jcmd = app { command = "usr/jcmd" },
            jconsole = app { command = "usr/jconsole" },
            jdb = app { command = "usr/jdb" },
            jdeprscan = app { command = "usr/jdeprscan" },
            jdeps = app { command = "usr/jdeps" },
            jfr = app { command = "usr/jfr" },
            jhsdb = app { command = "usr/jhsdb" },
            jimage = app { command = "usr/jimage" },
            jinfo = app { command = "usr/jinfo" },
            jlink = app { command = "usr/jlink" },
            jmap = app { command = "usr/jmap" },
            jmod = app { command = "usr/jmod" },
            jpackage = app { command = "usr/jpackage" },
            jps = app { command = "usr/jps" },
            jrunscript = app { command = "usr/jrunscript" },
            jshell = app { command = "usr/jshell" },
            jstack = app { command = "usr/jstack" },
            jstat = app { command = "usr/jstat" },
            jstatd = app { command = "usr/jstatd" },
            jwebserver = app { command = "usr/jwebserver" },
            keytool = app { command = "usr/keytool" },
            rmiregistry = app { command = "usr/rmiregistry" },
            serialver = app { command = "usr/serialver" },
        },
    },
}
