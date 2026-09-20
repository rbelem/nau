-- Fixture: a definition declaring a node (ADR-0033 Decision 6).
-- The node table must ride the eval payload as NodeConfig, NOT leak
-- into the snap outputs.
return {
    default = snap {
        name = "shared",
        version = "2.0",
    },
    node = node {
        name = "devbox",
        serve = { address = "127.0.0.1:7780", announce = true },
        peers = { "shuttle://nuci.local:7780" },
    },
}
