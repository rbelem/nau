-- Common snap template for reuse across configs.
-- Per ADR-0004: returns a table — no mutation, no side effects.

return {
    name = "app-template",
    version = "0.1.0",
    summary = "A snap built with shuttle",
    grade = "stable",
    confinement = "strict",
    apps = {
        default = {
            command = "bin/app",
        },
    },
}
