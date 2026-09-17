-- tree-sitter-perl: Perl grammar for tree-sitter (Python package).
--
-- Ported from devbox-global's devbox.d/tree-sitter-perl flake (the same
-- recipe is embedded in the codegraph and graphify flakes). The v2.0.0
-- tag ships src/grammar.json but no generated parser.c, so the flake's
-- preBuild is the build: `tree-sitter generate src/grammar.json`
-- materializes parser.c plus the src/tree_sitter/ runtime headers
-- (parser.h/array.h), then upstream's pyproject/setuptools packaging is
-- discarded for a minimal project written by hand — a one-function
-- tree_sitter_perl/__init__.py, a binding.c exposing tree_sitter_perl()
-- as a PyCapsule, and a setup.py building the limited-API extension
-- (Py_LIMITED_API=0x030A0000 → abi3) from binding.c + src/parser.c +
-- src/scanner.c. Pure C (the external scanner is scanner.c, not C++),
-- so the .so needs neither libstdcpp nor libgcc. Library-only — no
-- console scripts, no apps; consumers import it from a pod python3.
--
-- Requires: glibc
-- build_deps: tree-sitter (the CLI that generates parser.c; invoked via
-- $SHUTTLE_BUILD_PREFIX — the merged prefix is not on PATH) and python
-- (setup.py interpreter plus Python.h for the extension build).
--
-- Distutils links the extension with the sandbox's nix gcc wrapper,
-- which bakes RUNPATH=/shuttle-build-prefix/usr/lib into produced
-- binaries: same interim leak-scan escape as dconf/htop/tmux
-- (ADR-0018 Decision 3, issue #22).

return {
    default = snap {
        name = "tree-sitter-perl",
        version = "2.0.0",
        summary = "Perl grammar for tree-sitter",
        description = [[
            Perl grammar for the tree-sitter parser generator, as a
            Python package: tree_sitter_perl.language() returns the
            compiled language capsule for use with the py-tree-sitter
            Language binding. Built abi3 (Python 3.10+ limited API), so
            one binary serves the pod's python3.
        ]],
        license = "MIT",
        grade = "stable",
        confinement = "strict",
        architectures = { "amd64" },

        source = {
            url = "https://github.com/tree-sitter-perl/tree-sitter-perl/archive/refs/tags/v2.0.0.tar.gz",
            sha256 = "97a70e75cbeb5516021b2eeff0121edf7a70de7077dd0d6ec83e54bb39e5897d",
        },

        -- Faithful translation of the flake's preBuild + setuptools
        -- build; joined with newlines because of the heredocs. The pool
        -- python is invoked by its merged-prefix path so sysconfig
        -- resolves Python.h inside the prefix (python-build-standalone
        -- stages include/python3.14 there).
        build = table.concat({
            "\"$SHUTTLE_BUILD_PREFIX/usr/bin/tree-sitter\" generate src/grammar.json",
            "rm -f setup.py pyproject.toml",
            "mkdir -p tree_sitter_perl",
            "cat > tree_sitter_perl/__init__.py <<'EOF'",
            "\"\"\"Perl grammar for tree-sitter.\"\"\"",
            "from ._binding import language",
            "EOF",
            "cat > binding.c <<'EOF'",
            "#include <Python.h>",
            "",
            "typedef struct TSLanguage TSLanguage;",
            "TSLanguage *tree_sitter_perl(void);",
            "",
            "static PyObject *_language(PyObject *self, PyObject *args) {",
            "    return PyCapsule_New(tree_sitter_perl(), \"tree_sitter.LANGUAGE\", NULL);",
            "}",
            "",
            "static PyMethodDef _methods[] = {",
            "    {\"language\", _language, METH_NOARGS, \"Get the tree-sitter language for this grammar.\"},",
            "    {NULL, NULL, 0, NULL}",
            "};",
            "",
            "static struct PyModuleDef _module = {",
            "    PyModuleDef_HEAD_INIT, \"_binding\", NULL, -1, _methods",
            "};",
            "",
            "PyMODINIT_FUNC PyInit__binding(void) {",
            "    return PyModule_Create(&_module);",
            "}",
            "EOF",
            "cat > setup.py <<'EOF'",
            "from setuptools import Extension, setup",
            "",
            "setup(",
            "    name=\"tree-sitter-perl\",",
            "    version=\"2.0.0\",",
            "    packages=[\"tree_sitter_perl\"],",
            "    ext_package=\"tree_sitter_perl\",",
            "    ext_modules=[",
            "        Extension(",
            "            name=\"_binding\",",
            "            sources=[\"binding.c\", \"src/parser.c\", \"src/scanner.c\"],",
            "            include_dirs=[\"src\"],",
            "            define_macros=[(\"Py_LIMITED_API\", \"0x030A0000\")],",
            "            py_limited_api=True,",
            "        )",
            "    ],",
            ")",
            "EOF",
            "\"$SHUTTLE_BUILD_PREFIX/usr/bin/python3\" setup.py build_ext --inplace",
            -- The flake's pythonImportsCheck, against the built tree.
            "PYTHONPATH=$PWD \"$SHUTTLE_BUILD_PREFIX/usr/bin/python3\" -c \"import tree_sitter_perl\"",
            -- Stage as the whichllm pattern, minus console scripts.
            "mkdir -p $STAGE/usr/lib/python3.14/site-packages",
            "cp -r tree_sitter_perl $STAGE/usr/lib/python3.14/site-packages/",
        }, "\n"),

        type = "source",
        requires = { "glibc" },
        build_deps = { "tree-sitter", "python" },

        -- Same interim leak-scan escape as dconf/htop/tmux: produced
        -- .so carries RUNPATH=/shuttle-build-prefix/usr/lib (dead at
        -- runtime). Silenced here, visibly logged by the leak scan,
        -- pending the RUNPATH repair.
        leaks_ok = { "/shuttle-build-prefix/usr/lib" },
    },
}
