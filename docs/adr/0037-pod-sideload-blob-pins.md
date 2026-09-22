# Pod sideload: `pod add --snap` blob pins

## Status

Accepted (2026-09-22). Implements issue #116. Extends ADR-0015 (pods:
user-level package management) and ADR-0021 (no `stage-packages`/`.deb`
ingestion — snap content is source-built or store-pinned). Grounded in the
2026-09-19 evaluation findings recorded in the issue: `install_batch` is
already blob-driven, and the pod lockfile already carries both pin
sections.

## Context

Pods resolve every package through the shared collection and build from
source. No path installs a prebuilt `.snap` payload into a pod — yet the
install machinery itself is already blob-driven: `RuntimeStore::install_batch`
consumes a `PendingSnap`, verifies sha3-384 fail-closed, unpacks with
unsquashfs, reads `meta/snap.yaml`, and ingests the tree. The system axis
has three blob sources (`shuttle install`, `pull --install`, `upgrade`);
the pod axis is the missing seam.

The gap binds to ADR-0021's model: pods compose by REBUILDING — a loading
pod's packages are rebuilt into its store from collection source. Any
ingestion path that bypasses the collection must therefore also say what
`pod sync` (which resolves every package through `load_meta`) does with it.

## Decision

1. **`shuttle pod add --snap <path> --ack-unsigned`** installs a
   shuttle-built `.snap` payload into the selected pod. The positional
   `package` arg becomes required-unless-`--snap`; the two conflict.

2. **Identity from the payload.** Name and version come from the
   payload's `meta/snap.yaml`. When the filename parses as
   `{name}_{version}_{arch}.snap`, a mismatch with `meta/snap.yaml`
   refuses fail-closed. v1 supports only shuttle-built payload shapes;
   snapcraft-built payloads are an explicit non-goal.

3. **Trust gate at the CLI.** Every sideload is unsigned in v1 (no
   pod-side signatures), so `--ack-unsigned` is required — without it the
   command refuses before any write (snapd's `snap install --dangerous`
   precedent). With it, the unsigned note rides the install. The
   `SignatureEnvelope` parameter stays wired for a signing follow-up.
   Infrastructure-type payloads (`base`/`gadget`/`kernel`/`snapd`) are
   refused; `type: store` payloads warn ("records only, nothing
   executable") and proceed as inert records — the same classification
   `install_batch` already applies.

4. **Blob pins.** `add` writes BOTH lockfile entries: a `packages` entry
   (version pin — existing tooling keeps working) and a `snaps` entry
   (name, revision 0, sha3-384). Revision 0 is the sideload sentinel;
   sha3-384 carries all discrimination. `pod remove` drops both.

5. **Re-add semantics at the pin.** Identical content re-add is a no-op.
   The same name+version with DIVERGENT bytes is refused, naming both
   hashes: a rebuild of the same version is byte-identical (deterministic
   builds), so same-version divergence is tamper, and the version pin is
   the trust anchor a swap would break. A version move is a deliberate
   re-add with a NEW version's payload — both pins move, a new generation
   carries the new content. (This reads issue #116 Decision 2's "changed
   content produces a new generation" as the version-move path, and
   copies `pending_from_blob`'s divergent-hash refusal to the
   same-version case.) The tamper refusal guards EXISTING blob pins
   only: a payload whose name matches a declared COLLECTION package
   converts that package to a blob pin — including at the same version,
   with bytes no collection build produced. That conversion is allowed
   but loud: the same zero-writes composition prechecks a new package
   goes through (`validate_loads` / `validate_overlays` /
   `precheck_payload_collisions`) run first, and a warning names the
   converted package — the collection recipe stops governing its
   content.

6. **Hold without the collection.** Blob-pinned packages never resolve
   through `load_meta`. `pod sync` holds them when the active generation
   carries the pinned sha3-384: claims (desktop IDs, binaries, services)
   come from the installed record, and the package's runtime `requires`
   still seed the closure. A pin whose content the generation does not
   carry fails named — the repair is a re-add, not a phantom rebuild.

7. **Composition refuses, fail-closed.** Loading a pod whose lockfile
   carries blob pins fails in `validate_loads` — before any write,
   naming the loaded pod, the pinned packages, and issue #116. A loading
   pod rebuilds its loads from collection source; a blob-pinned package
   has none. Blob-copy across pods is deferred. The refusal walks the
   loading pod's OWN load graph, which leaves a second edge open:
   sideloading INTO pod B while pod A already loads B leaves A's
   mutating verbs refused (naming B's new pin) until B's pin is
   removed — B gained content A cannot rebuild, and A's verbs fail
   closed rather than silently dropping B from the graph.

8. **Blob pins never float.** `pod update` skips blob pins with a named
   note ("re-add with a new `--snap` to move"), and `deps fetch` skips
   them too — both would otherwise die in collection resolution for a
   package that was never a collection package (fatally on a
   collection-less pod). `pod rebuild` of a blob-pinned package holds it
   at its pin and says so ("held '<name>' at its pin"), never reporting
   a rebuild. `rollback` works unchanged through the existing generation
   switch. `remove` is pin-aware: it drops BOTH pins (Decision 4), so a
   plain sync after it does not fail named on a pin whose content is
   gone.

## Alternatives considered

- **Divergent same-version re-add installs as a new generation.**
  Rejected: shuttle builds are deterministic, so the same
  name+version with different bytes is not a rebuild — it is foreign
  content behind a trusted name. `pending_from_blob` refuses exactly
  this shape; the pod pin copies the rule.
- **Gate the sideload inside `install_batch`.** Rejected: the
  acknowledgment and identity checks must run BEFORE the declaration and
  lockfile writes, or a refused sideload leaves half-initialized pod
  state. The CLI-side gate keeps refusal zero-write.
- **Install the payload through `sync`'s pending queue.** Rejected for
  v1: it would thread a payload path through the reconcile state. The
  direct `install_batch` call (then a reconcile around the installed
  content) reuses the store's verified path with no new plumbing.

## Consequences

**Positive**: the pod axis gains the same blob-source seam the system
axis already has; a collection-less machine can reproduce a pod from
payloads that carry no `requires` closures (a requires closure still
resolves through the collection, so those pods need it present at sync
time); pins stay content-addressed and fail-closed; `sync` stays a
no-op holder instead of dying in `load_meta`.

**Negative**: every sideload is unsigned in v1 (`--ack-unsigned` is the
honest spelling of that); loading a sideload-carrying pod refuses until
blob-copy lands; a payload whose build is NOT deterministic (foreign
toolchains) cannot be re-added under the same version — bump the version
or remove first.

**Neutral**: `type: store` sideloads are inert records by the existing
runtime rule; `pod rebuild` of a blob-pinned package holds (reports it)
instead of rebuilding — the payload, not a recipe, is the content.
