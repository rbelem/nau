use super::*;
use tempfile::tempdir;

fn sample_entry() -> IndexEntry {
    IndexEntry {
        name: "core22".into(),
        summary: Some("Ubuntu 22.04 base".into()),
        store: Some(StoreRef {
            name: Some("core22".into()),
            channel: "latest/stable".into(),
        }),
        pins: {
            let mut map = HashMap::new();
            map.insert(
                    "amd64".into(),
                    PinEntry {
                        revision: 2411,
                        sha3_384: "e7bba49dc406968eb0a127e2c405c268c4abe875120f2c4930129800624bd937618069adbcc47cf3762aceddd1c4b977".into(),
                        channel: Some("latest/stable".into()),
                    },
                );
            Some(map)
        },
        source: None,
        build: None,
        apps: None,
        aliases: vec![],
    }
}

fn pin(revision: u32, channel: Option<&str>) -> PinEntry {
    PinEntry {
        revision,
        sha3_384: "a".repeat(96),
        channel: channel.map(str::to_string),
    }
}

fn pins_with(entries: Vec<(String, PinEntry)>) -> HashMap<String, PinEntry> {
    entries.into_iter().collect()
}

mod test_index;
