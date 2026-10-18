use super::*;

    #[test]
    fn test_source_validators_reject_weak_etag_and_expired_stamp() {
        let entry = |etag: Option<&str>, validated_at: Option<u64>| SourceLockEntry {
            sha256: "abc123".to_string(),
            etag: etag.map(str::to_string),
            validated_at,
        };
        let now = 1_800_000_000;
        // A weak etag (`W/` prefix) is rejected → treated as absent, so a
        // conditional probe never sends it.
        assert!(entry(Some("W/\"weak-1\""), Some(now))
            .validators(now)
            .is_none());
        // No etag, no stamp: nothing to probe with.
        assert!(entry(None, Some(now)).validators(now).is_none());
        assert!(entry(Some("\"strong\""), None).validators(now).is_none());
        // Exactly at the TTL boundary it is still valid; one second past
        // it has expired (a full GET must re-anchor).
        assert!(entry(Some("\"strong\""), Some(now - VALIDATOR_TTL_SECS))
            .validators(now)
            .is_some());
        assert!(
            entry(Some("\"strong\""), Some(now - VALIDATOR_TTL_SECS - 1))
                .validators(now)
                .is_none()
        );
        // A stamp from the future does not panic (saturating compare).
        assert!(entry(Some("\"strong\""), Some(now + 60))
            .validators(now)
            .is_some());
    }
