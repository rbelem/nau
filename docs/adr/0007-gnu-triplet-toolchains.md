# GNU target triplet toolchain naming

Toolchain meta-packages use the GNU target triplet convention: `toolchain-<compiler>-<libc>-<arch>` (e.g. `toolchain-gcc-gnu-x86_64`). This is the standard naming scheme in the cross-compilation ecosystem, matches how autotools and GCC expect `--target` flags, and makes it immediately clear what a toolchain provides. The alternative (arbitrary names like `gcc-toolchain` or `native`), while shorter, would lose the structured information needed for multi-target builds. Short aliases (`toolchain`, `toolchain-x86_64`) are provided for convenience.
