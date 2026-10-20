use super::*;
use std::sync::Mutex;

fn seeds_meta(name: &str, requires: &[&str], build_deps: &[&str]) -> SnapMeta {
    SnapMeta {
        name: name.into(),
        version: "1.0".into(),
        summary: None,
        description: None,
        license: None,
        source: None,
        sources: None,
        build: Some("make".into()),
        parts: None,
        architectures: Some(vec!["amd64".into()]),
        grade: "stable".into(),
        confinement: "strict".into(),
        type_: Some("source".into()),
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
        requires: requires.iter().map(|s| s.to_string()).collect(),
        build_deps: build_deps.iter().map(|s| s.to_string()).collect(),
        leaks_ok: vec![],
        target: None,
        toolchain: None,
        inputs: None,
        confined: None,
        apps: std::collections::BTreeMap::new(),
        services: std::collections::BTreeMap::new(),
        deps: None,
        floating: false,
        definition_dir: None,
    }
}

static INPUTS_LOCK: Mutex<()> = Mutex::new(());

fn init_local_input_source(root: &Path) {
    crate::pkg_source::init_global_inputs(&HashMap::from([(
        "test".to_string(),
        nau_core::snap_types::PackageInput {
            url: format!("path:{}", root.display()),
            submodules: None,
        },
    )]))
    .unwrap();
}

mod test_build_view;
mod test_topological;
