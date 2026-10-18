use super::*;

#[test]
fn parse_address_splits_user_host_port() {
    let a = addr(Some("op"), "nuci.local", None).unwrap();
    assert_eq!(a.user.as_deref(), Some("op"));
    assert_eq!(a.host, "nuci.local");
    assert_eq!(a.port, None);

    let a = addr(Some("op"), "nuci.local", Some(2222)).unwrap();
    assert_eq!(a.port, Some(2222));

    let a = addr(None, "::1", Some(22)).unwrap();
    assert_eq!(a.host, "::1");
    assert_eq!(a.port, Some(22));
}

#[test]
fn parse_address_refuses_injection_shapes() {
    // The #189 guard posture, re-asserted at the executor boundary.
    assert!(addr(Some("op"), "-oProxyCommand=evil", None).is_err());
    assert!(parse_address("ssh://-oProxyCommand=x@h").is_err());
    assert!(parse_address("ssh://@h").is_err());
    assert!(parse_address("ssh://h:0").is_err());
    assert!(parse_address("ssh://h:99999").is_err());
    assert!(parse_address("http://h").is_err());
}

#[test]
fn sha_shape_is_strict() {
    let hex = "a".repeat(64);
    assert!(is_sha256(&hex));
    assert!(!is_sha256(&"A".repeat(64)), "uppercase is not the shape");
    assert!(!is_sha256(&"a".repeat(63)));
}

#[test]
fn remote_filenames_are_plain_names_only() {
    assert!(validate_remote_filename("htop_3.3.0_amd64.snap").is_ok());
    assert!(validate_remote_filename("a-b_c9.snap").is_ok());
    assert!(validate_remote_filename("../escape.snap").is_err());
    assert!(validate_remote_filename("dir/x.snap").is_err());
    assert!(validate_remote_filename(".hidden").is_err());
    assert!(validate_remote_filename("x;y.snap").is_err());
    assert!(validate_remote_filename("").is_err());
}
