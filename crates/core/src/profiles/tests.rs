use super::*;
use std::os::unix::fs::symlink;

fn profile() -> ViewProfile {
    ViewProfile {
        tree_order: vec!["host".into(), "service".into(), "name".into()],
        facets: BTreeMap::from([(
            "namespace".into(),
            ProfileFacet {
                mode: ProfileFacetMode::Whitelist,
                selected: BTreeSet::from(["example".into()]),
            },
        )]),
        view_filter: ProfileViewFilter::Passwords,
        human_only: false,
    }
}

#[test]
fn round_trip_cas_reopen_and_public_metadata_only() {
    let directory = tempfile::tempdir().unwrap();
    let store = ProfileStore::new(directory.path()).unwrap();
    let initial = store.list().unwrap();
    let saved = store.save("My view", profile(), initial.revision).unwrap();
    assert_eq!(saved.profiles["My view"], profile());
    assert!(store.save("stale", profile(), initial.revision).is_err());
    let path = directory.path().join("nix-secrets-profiles.toml");
    let text = fs::read_to_string(&path).unwrap();
    assert!(text.contains("namespace"));
    assert!(!text.contains("age_ciphertext"));
    assert!(!text.contains("secret_value"));
    assert_eq!(
        ProfileStore::new(directory.path()).unwrap().list().unwrap(),
        saved
    );
    let empty = store.delete("My view", saved.revision).unwrap();
    assert!(empty.profiles.is_empty());
}

#[test]
fn rejects_malformed_unknown_and_symlinked_profile_files() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("nix-secrets-profiles.toml");
    fs::write(&path, "version = 2\n").unwrap();
    assert!(ProfileStore::new(directory.path()).unwrap().list().is_err());
    fs::write(&path, "version = 1\nsecret_value = 'oops'\n").unwrap();
    assert!(ProfileStore::new(directory.path()).unwrap().list().is_err());
    fs::remove_file(&path).unwrap();
    let elsewhere = directory.path().join("elsewhere");
    fs::write(&elsewhere, "version = 1\n").unwrap();
    symlink(&elsewhere, &path).unwrap();
    assert!(ProfileStore::new(directory.path()).is_err());
}

#[test]
fn rejects_unknown_facets_and_control_characters() {
    let directory = tempfile::tempdir().unwrap();
    let store = ProfileStore::new(directory.path()).unwrap();
    let mut invalid = profile();
    invalid.tree_order.push("not-an-attribute".into());
    assert!(store.save("test", invalid, 0).is_err());
    assert!(store.save("escape\nname", profile(), 0).is_err());
}
