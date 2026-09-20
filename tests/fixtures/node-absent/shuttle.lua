-- Fixture: a definition without node{} (ADR-0033 Decision 6: absent
-- node() = nothing). Eval must carry no NodeConfig.
return {
    default = snap {
        name = "plain",
        version = "1.0",
    },
}
