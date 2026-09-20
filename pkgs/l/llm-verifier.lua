-- llm-verifier: LLM-as-a-Verifier — fine-grained verification framework
-- for agent best-of-N selection (Python library).
--
-- Ported from devbox-global's devbox.d/llm-verifier flake. The flake
-- fetchurl-pins the PyPI sdist (fetchurl, not fetchPypi: PyPI's PEP-625
-- normalization names the sdist llm_verifier-*.tar.gz with an underscore,
-- which fetchPypi's hyphenated URL 404s on — the same trap this port
-- avoids by pinning the exact files.pythonhosted.org URL). The pinned
-- tarball's sha256 (c5eb85902344…) matches the flake's SRI hash
-- (sha256-xeuFkCNEyjaAybBF8y4H7bXKxmjkvEL/Kpa4B3jWKKo=) byte-for-byte.
--
-- DEPENDENCY CLOSURE — KNOWN GAP, DELIBERATE: the flake propagates
-- google-genai, openai, and tqdm from nixpkgs, which resolves versions at
-- eval time. The shuttle pip resolver (ADR-0017) is lock-driven, but this
-- sdist ships NO lockfile (no uv.lock, no requirements.lock — verified
-- against the pinned artifact), and the upstream GitHub repo named in the
-- metadata is gone, so no lock artifact exists to pin against. Declaring
-- deps.pip here would require inventing version pins, so no deps block is
-- declared. All three deps are imported lazily (function-local imports in
-- fine_grained_reward.py), so `import llm_verifier` succeeds and the
-- verification primitives load; calling the OpenAI/Gemini-backed
-- verifiers raises ModuleNotFoundError until the closure lands upstream.
--
-- Library-only, matching the flake (whose default output is
-- python3.withPackages — an interpreter closure, no CLI): no console
-- scripts upstream, no apps here. Consumers import it from a pod python3.
--
-- Requires: glibc (pure Python; staged like whichllm minus the deps and
--           console script)
-- build_deps: (none)

return {
    default = snap {
        name = "llm-verifier",
        version = "0.2.0",
        summary = "LLM-as-a-Verifier: verification framework for agent best-of-N selection",
        description = [[
            llm_verifier scores agent trajectories with fine-grained
            LLM rewards and selects best-of-N via Pivot Preference
            Tournaments. Entry points: select (best of N), compare
            (pairwise rewards), and track (per-step progress). The
            OpenAI- and Gemini-backed verifiers import their SDKs
            lazily; the dependency closure (google-genai, openai,
            tqdm) is not yet pinned — see the header note.
        ]],
        license = "MIT",
        grade = "stable",
        confinement = "strict",
        architectures = { "amd64" },

        source = {
            url = "https://files.pythonhosted.org/packages/27/b7/6f91acc8898dc8e00e5a0826feb9437c6ac80ea335f7b6558ba76e2b59b6/llm_verifier-0.2.0.tar.gz",
            sha256 = "c5eb85902344ca3680c9b045f32e07edb5cac668e4bc42ff2a96b80778d628aa",
        },

        build = table.concat({
            "mkdir -p $STAGE/usr/lib/python3.14/site-packages",
            -- Pure Python, single-package sdist ([tool.setuptools]
            -- packages = ["llm_verifier"]); py.typed rides along.
            "cp -r $SRC/llm_verifier $STAGE/usr/lib/python3.14/site-packages/",
        }, " && "),

        type = "source",
        requires = { "glibc" },
    },
}
