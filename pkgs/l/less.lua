-- less: Pager program similar to more
--
-- Source: https://www.greenwoodsoftware.com/less/
-- Provides the less file pager for terminal viewing.

return {
    default = snap {
        name = "less",
        version = "661",
        summary = "Pager program similar to more",
        description = [[
            less is a terminal pager program similar to more, but with
            many enhancements. It allows backward movement as well as
            forward movement in the file. It does not have to read the
            entire input file before starting, so it starts faster with
            large input files. Supports searching, line numbers, and
            syntax highlighting.
        ]],
        grade = "stable",
        confinement = "strict",
        architectures = { "amd64", "arm64", "armhf" },
        type = "source",
        requires = { "glibc", "ncurses" },
        source = {
            url = "https://www.greenwoodsoftware.com/less/less-661.tar.gz",
        },
        build = "./configure --prefix=/usr && make && make install DESTDIR=$STAGE",
    },
}
