use super::*;

    #[test]
    fn render_emits_required_keys_and_escapes_exec() {
        let l = launcher(Some("My App"), &["Graphics", "Viewer"]);
        let exec = std::path::Path::new("/home/u/.local/share/nau/pods/default/current/myapp");
        let text = render(&l, "myapp", exec, Some("nau-pod-default-myapp"));
        assert!(text.starts_with("[Desktop Entry]\n"));
        assert!(text.contains("Type=Application\n"));
        assert!(text.contains("Name=My App\n"));
        assert!(text.contains("Icon=nau-pod-default-myapp\n"));
        assert!(text.contains("Categories=Graphics;Viewer;\n"));
        assert!(text.contains("Exec=\""));
        assert!(text.contains("/home/u/.local/share/nau/pods/default/current/myapp\""));
        assert!(text.contains("Terminal=false\n"));
        // Round-trip through the validator — a strict conformance proof.
        validate(&text, Some("nau-pod-default-myapp"), None).unwrap();
    }

    #[test]
    fn render_escapes_newlines_tabs_and_spaces_in_values() {
        let mut l = launcher(Some("A\nB"), &["Utility"]);
        l.comment = Some(" padded ".into());
        l.icon_ref = Some("x".into());
        let text = render(&l, "a", std::path::Path::new("/usr/bin/a"), None);
        assert!(text.contains("Name=A\\nB\n"));
        assert!(text.contains("Comment=\\spadded\\s\n"));
    }

    #[test]
    fn name_falls_back_to_app_id() {
        let l = launcher(None, &["Utility"]);
        let text = render(&l, "mytool", std::path::Path::new("/bin/mytool"), None);
        assert!(text.contains("Name=mytool\n"));
    }

    #[test]
    fn exec_always_double_quoted_absolute() {
        let l = launcher(None, &["Utility"]);
        let text = render(&l, "a", std::path::Path::new("/bin/a"), None);
        let exec_line = text.lines().find(|l| l.starts_with("Exec=")).unwrap();
        assert!(exec_line.starts_with("Exec=\"/bin/a\""), "got {exec_line}");
    }

    #[test]
    fn unknown_category_fails_validation() {
        let l = launcher(Some("x"), &["NotRealCategory"]);
        let text = render(&l, "a", std::path::Path::new("/bin/a"), None);
        let err = validate(&text, None, None).unwrap_err().to_string();
        assert!(err.contains("unregistered category"), "got {err}");
    }

    #[test]
    fn missing_main_category_fails() {
        // "IDE" is registered but additional-only; a categories list with
        // no main category must be rejected.
        let l = launcher(Some("x"), &["IDE"]);
        let text = render(&l, "a", std::path::Path::new("/bin/a"), None);
        let err = validate(&text, None, None).unwrap_err().to_string();
        assert!(err.contains("at least one main category"), "got {err}");
    }

    #[test]
    fn icon_path_is_rejected() {
        let l = launcher(Some("x"), &["Utility"]);
        let text = render(
            &l,
            "a",
            std::path::Path::new("/bin/a"),
            Some("icons/app.png"),
        );
        let err = validate(&text, Some("icons/app.png"), None)
            .unwrap_err()
            .to_string();
        assert!(err.contains("not a path"), "got {err}");
    }

    #[test]
    fn exec_missing_absolute_or_broken_is_rejected() {
        let entry = |exec: &str| format!("[Desktop Entry]\nType=Application\nName=x\n{exec}\n");
        let err = validate(&entry("Exec=relative/path"), None, None)
            .unwrap_err()
            .to_string();
        assert!(err.contains("absolute path"), "got {err}");

        let err2 = validate(&entry("Exec=\"/unterminated"), None, None)
            .unwrap_err()
            .to_string();
        assert!(err2.contains("unclosed quotes"), "got {err2}");

        let err3 = validate(&entry("Exec=\"/bin/a\\z\""), None, None)
            .unwrap_err()
            .to_string();
        assert!(err3.contains("invalid escape"), "got {err3}");
    }

    #[test]
    fn strict_checker_passes_every_rendered_generated_shape() {
        // A representative generated entry (the exact shape the emitter
        // produces) must pass. This is the test-only conformance proof.
        let l = DesktopLauncher {
            name: Some("GUI Example".into()),
            generic_name: Some("Example".into()),
            comment: Some("Example interface".into()),
            categories: vec!["Graphics".into(), "Viewer".into()],
            icon_ref: None,
            icon: Some(nau_core::pkg_manifest::DesktopIcon {
                sha256: "abc".into(),
                ext: "png".into(),
            }),
        };
        let exec =
            std::path::Path::new("/home/u/.local/share/nau/pods/default/current/gui-example");
        let icon_name = "nau-pod-default-gui-example";
        let text = render(&l, "gui-example", exec, Some(icon_name));
        validate(&text, Some(icon_name), None).unwrap();
    }
