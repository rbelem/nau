# Fedora Silverblue Build Pipeline — Technical Brief

> **Purpose:** Dense reference on how Fedora Silverblue (Atomic Desktops: Kinoite, Sericea, Onyx) OS images are built — manifest formats, compose pipeline, distribution channel.
> **Companion:** `fedora-silverblue-runtime-brief.md` (ostree deployment/upgrade model).
> **Sources:** coreos.github.io/rpm-ostree/treefile, gitlab.com/fedora/bootc/base-images, github.com/blue-build, github.com/ublue-os, fedoraproject.org/atomic-desktops.
> **Date:** August 2026. Covers treefile era (2014–2024) and bootc era (2024+).

---

## 1. Era Timeline

| Era | Compose | Manifest | Distribution | Status |
|-----|---------|----------|--------------|--------|
| 2014–2016 | rpm-ostree + Koji + ImageFactory | JSON treefiles | ostree remote | dead |
| 2016–2024 | rpm-ostree compose tree + Koji + Pungi | YAML/JSON treefiles | ostree remote + static deltas | legacy, still supported |
| 2024+ | podman/buildah + Containerfile (bootc) | Containerfile (+ declarative wrappers) | OCI container registry | current |

Biggest shift: distribution moved from a bespoke ostree remote to plain container registries. The client-side ostree backend stayed the same (see runtime brief).

---

## 2. Era 1 — rpm-ostree compose tree

Pipeline: **Koji** builds RPMs → **Pungi** assembles a coordinated RPM snapshot → `rpm-ostree compose tree` turns treefile + RPM set into an ostree commit → published to ostree remote with static deltas → installer ISO via kickstart pointing at the ref.

```bash
ostree --repo=repo init --mode=archive-z2
rpm-ostree compose --repo=repo tree fedora-silverblue.yaml
```

### 2.1 Treefile format (the declarative manifest)

```yaml
# common.yaml
edition: 2024
ref: fedora/40/x86_64/silverblue
automatic_version_prefix: "40"
mutate-os-release: "40"

packages:            # rpm names to include
  - htop
exclude-packages:    # pulled in as deps but dropped
  - firefox
remove-from-packages:
  - kernel-modules-extra

postprocess:         # chrooted shell snippets after install
  - |
    #!/bin/bash
    systemctl mask tmp.mount
```

Per-variant include chain: `silverblue-common.yaml` has `include: common.yaml` + desktop package list. Same pattern for kinoite/sericea/onyx — one package list per desktop on a shared base.

Treefile key groups: identity (`ref`, `automatic_version_prefix`, `mutate-os-release`), package selection (`packages`, `exclude-packages`, `remove-from-packages`, `repos`, `bootstrap_packages`), build-time (`postprocess` scripts), output (`ostree-layers`, `ostree-override-layers`, `container-cmd`).

Official treefiles lived in the fedora-silverblue/fedora-kinoite repos (Pagure, later GitLab).

---

## 3. Era 2 — bootc / bootable containers (current)

Package set = git repo with a Containerfile. Standard `podman build` on a bootc base image. No special build infra required — GitHub Actions is enough.

### 3.1 Official pattern

```dockerfile
FROM quay.io/fedora/fedora-bootc:42
RUN dnf install -y gnome-... && dnf clean all
RUN systemctl enable gdm.service
LABEL com.github.containers.bootc=true
```

Base images: `quay.io/fedora/fedora-bootc`, `quay.io/fedora/fedora-silverblue` (desktop pre-baked). Official builds in `gitlab.com/fedora/bootc/base-images` and the atomic-desktops repos; release artifacts (.iso, .raw) produced downstream via osbuild-based tooling from the container image.

Note: **dnf in the Containerfile, not rpm-ostree** — rpm-ostree is a host-side ostree tool and does not work inside a container build.

### 3.2 Community builders (proof of demand)

- **Universal Blue** (`github.com/ublue-os/main`): Containerfiles + GitHub Actions, custom kernels/drivers via pre-built akmods images layered in build stages, ships to `ghcr.io/ublue-os/*`. Bazzite/Bluefin built this way.
- **BlueBuild** (`github.com/blue-build/bluebuild`): Rust CLI, declarative YAML recipe → generates Containerfile → builds with podman → pushes OCI image. CI-first design.

```yaml
# BlueBuild recipe module example
modules:
  - type: rpm-ostree
    install: [vim-enhanced, htop]
  - type: files
    files:
      - source: system/etc
        destination: /etc
```

Recipe keys: `base-image`, `image-version`, `platforms`, ordered `modules` (rpm-ostree, files, script, signing, ...). Same conceptual shape as a treefile: base + package list + file copies + scripts, declarative on top of an imperative build engine.

---

## 4. Distribution channel

### 4.1 ostree remote (era 1 / still valid)

```
/repo/
  objects/<2-hex>/<hash>.file|.dirtree|.dirmeta|.commit
  refs/heads/fedora/40/x86_64/silverblue   # file containing commit SHA
  summary                                   # remote metadata
  static-delta/                             # pre-computed commit-to-commit diffs
```

Clients pull refs; static deltas avoid full-tree downloads.

### 4.2 Container registry (era 2)

OCI image = base layer + desktop layers + custom layers, with `com.github.containers.bootc=true` label. Any registry (quay, ghcr, docker.io). Client pulls via containers/image stack into the local ostree store — details in runtime brief.

---

## 5. Relevance to shoot

- **Treefile = Silverblue's declaration**: ref/name + package list + exclusions + postprocess scripts. Exact conceptual analog of shoot's Lua manifest.
- Era-2 lesson: ecosystem rejected imperative-only Dockerfiles as UX → BlueBuild re-added declarative YAML wrapper. Declarative front end over an imperative engine wins.
- Era-2 lesson: build infra collapsed to "anyone with a container builder + CI". No dedicated compose server needed once artifact = OCI image.
- Layering escape hatch (`rpm-ostree install`) is always slower than baked-in packages — argument for baking declarations into the artifact at build time (shoot's model) rather than client-side mutation.

---

## Sources

- rpm-ostree treefile reference: https://coreos.github.io/rpm-ostree/treefile/
- rpm-ostree compose: https://coreos.github.io/rpm-ostree/compose-server/
- Fedora bootc base images: https://gitlab.com/fedora/bootc/base-images
- Fedora Atomic Desktops: https://fedoraproject.org/atomic-desktops/
- Universal Blue: https://github.com/ublue-os/main
- BlueBuild: https://github.com/blue-build/bluebuild
- bootc: https://github.com/bootc-dev/bootc
