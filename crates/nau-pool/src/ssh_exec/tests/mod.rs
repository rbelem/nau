use super::*;

fn addr(user: Option<&str>, host: &str, port: Option<u16>) -> miette::Result<AddressParts> {
    let mut s = String::from("ssh://");
    if let Some(u) = user {
        s.push_str(u);
        s.push('@');
    }
    if host.contains(':') {
        s.push('[');
        s.push_str(host);
        s.push(']');
    } else {
        s.push_str(host);
    }
    if let Some(p) = port {
        s.push_str(&format!(":{p}"));
    }
    parse_address(&s)
}

mod parse_address;
