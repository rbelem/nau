
use super::*;

fn launcher(name: Option<&str>, cats: &[&str]) -> DesktopLauncher {
    DesktopLauncher {
        name: name.map(str::to_string),
        generic_name: None,
        comment: None,
        categories: cats.iter().map(|s| s.to_string()).collect(),
        icon_ref: None,
        icon: None,
    }
}

mod render_emits;
