
use super::*;

fn dep_fixture_meta(name: &str) -> crate::snap::SnapMeta {
    crate::snap::SnapMeta {
        name: name.into(),
        version: "1.0".into(),
        summary: None,
        description: None,
        license: None,
        source: None,
        sources: None,
        build: None,
        parts: None,
        architectures: None,
        grade: "stable".into(),
        confinement: "strict".into(),
        type_: None,
        adopt_info: None,
        version_adopted: false,
        icon_source: None,
        icon: None,
        compression: None,
        compression_level: None,
        environment: None,
        layout: None,
        hooks: None,
        plugs: None,
        slots: None,
        aliases: vec![],
        requires: vec![],
        build_deps: vec![],
        leaks_ok: vec![],
        target: None,
        toolchain: None,
        inputs: None,
        confined: None,
        apps: BTreeMap::new(),
        services: BTreeMap::new(),
        deps: None,
        floating: false,
        definition_dir: None,
    }
}

fn tool_on_path(tool: &str) -> bool {
    std::process::Command::new("which")
        .arg(tool)
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

mod test_names;
