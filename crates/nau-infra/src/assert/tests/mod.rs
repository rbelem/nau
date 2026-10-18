
    use super::*;

    /// Real snap-revision + account-key assertions captured from the live
    /// store (hello-world rev 29, the smallest published snap). The tests
    /// exercise the exact production verification path offline and
    /// deterministically.
    const SNAP_REVISION: &str =
        include_str!("../../../../../tests/fixtures/assertions/hello-world-rev29.snap-revision.assert");
    const STORE_ACCOUNT_KEY: &str =
        include_str!("../../../../../tests/fixtures/assertions/store.account-key.assert");

    const HELLO_SNAP_ID: &str = "buPKUD3TKqCOgLEjjHx5kSiCpIs5cMuQ";
    const HELLO_DIGEST_HEX: &str = "b07bdb78e762c2e6020c75fafc92055b323a6f8da3ab42a3963da5ade386aba11f77e3c8f919b8aa23f3aa5c06c844f9";
    const HELLO_SIZE: u64 = 20480;

    fn chain(revision: u32) -> Result<(), AssertError> {
        verify_chain(
            "hello-world",
            SNAP_REVISION,
            STORE_ACCOUNT_KEY,
            Some(HELLO_SNAP_ID),
            revision,
            &hex_decode("hello-world", "digest", HELLO_DIGEST_HEX).unwrap(),
            Some(HELLO_SIZE),
        )
    }

    /// Flip one character of the base64 body block (part of the signed
    /// wire content) without breaking base64 validity.
    fn tamper_body_first_char(text: &str) -> String {
        let (head, rest) = text.split_once("\n\n").unwrap();
        let (body, sig) = rest.split_once("\n\n").unwrap();
        let mut c: Vec<char> = body.chars().collect();
        c[0] = if c[0] == 'A' { 'B' } else { 'A' };
        let body: String = c.into_iter().collect();
        format!("{head}\n\n{body}\n\n{sig}")
    }

    fn chain_with(revision: u32, account_key: &str) -> Result<(), AssertError> {
        verify_chain(
            "hello-world",
            SNAP_REVISION,
            account_key,
            Some(HELLO_SNAP_ID),
            revision,
            &hex_decode("hello-world", "digest", HELLO_DIGEST_HEX).unwrap(),
            Some(HELLO_SIZE),
        )
    }


mod test_valid;
