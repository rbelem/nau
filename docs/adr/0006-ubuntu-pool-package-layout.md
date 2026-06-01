# Ubuntu pool package layout (flat by-name)

Packages in `pkgs/` follow the Ubuntu archive pool convention: `pkgs/<first-letter>/<name>.lua` for single-file packages, `pkgs/<first-letter>/<name>/init.lua` for multi-file packages. This avoids deep nesting (no category hierarchy), makes packages discoverable by name alone, and scales to thousands of entries without deep tree navigation. The alternative (category-based: `pkgs/devel/gcc.lua`, `pkgs/net/curl.lua`) requires category decisions that inevitably become arbitrary and inconsistent.
