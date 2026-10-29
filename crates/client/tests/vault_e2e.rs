//! Deniable vaults end to end (docs/deniable-drives.md) with the software authenticator.

use std::path::Path;
use std::sync::Arc;

use strongbox_client::vault::{connect, connect_account, connect_with_recovery, create_vault};
use strongbox_client::{Error, OnConflict, TransferOptions};
use strongbox_fido::soft::SoftAuthenticator;
use strongbox_fido::Authenticator;
use strongbox_proto::RegistrationMode;
use strongbox_server::Config;

const SLOTS: u32 = 4;
const BLOCKS: u32 = 16;

async fn start_server(data_dir: &Path) -> String {
    start_server_with_admin(data_dir).await.0
}

/// Service URL and admin page URL (separate listeners).
async fn start_server_with_admin(data_dir: &Path) -> (String, String) {
    start_server_sized(data_dir, SLOTS, BLOCKS).await
}

async fn start_server_sized(data_dir: &Path, slots: u32, blocks: u32) -> (String, String) {
    let config = Config {
        listen: "127.0.0.1:0".parse().unwrap(),
        admin_listen: "127.0.0.1:1".parse().unwrap(),
        data_dir: data_dir.to_path_buf(),
        registration: RegistrationMode::Invite,
        invite_token: Some("letmein".into()),
        session_ttl_secs: 3600,
        prelogin_rate_per_minute: 1000,
        trust_proxy: false,
        debug: false,
        vault_slots: Some(slots),
        vault_slot_blocks: Some(blocks),
        drive_size: None,
        spare_vaults: 0,
    };
    let (app, admin) = strongbox_server::build_all(config).await.unwrap();
    let mut urls = Vec::new();
    for router in [app, admin] {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        urls.push(format!("http://{}", listener.local_addr().unwrap()));
        tokio::spawn(async move {
            axum::serve(
                listener,
                router.into_make_service_with_connect_info::<std::net::SocketAddr>(),
            )
            .await
            .unwrap()
        });
    }
    (urls.remove(0), urls.remove(0))
}

fn contains(hay: &[u8], needle: &[u8]) -> bool {
    hay.windows(needle.len()).any(|w| w == needle)
}

fn vault_files(server_dir: &Path) -> Vec<std::path::PathBuf> {
    let mut out = Vec::new();
    for v in std::fs::read_dir(server_dir.join("vaults")).unwrap() {
        for f in std::fs::read_dir(v.unwrap().path()).unwrap() {
            out.push(f.unwrap().path());
        }
    }
    out.sort();
    out
}

#[tokio::test(flavor = "multi_thread")]
async fn deniable_vault() {
    let tmp = tempfile::tempdir().unwrap();
    let server_dir = tmp.path().join("server");
    let local = tmp.path().join("local");
    std::fs::create_dir_all(&local).unwrap();
    let url = start_server(&server_dir).await;
    let key: Arc<dyn Authenticator> =
        Arc::new(SoftAuthenticator::new(tmp.path().join("key1.json")));
    let backup: Arc<dyn Authenticator> =
        Arc::new(SoftAuthenticator::new(tmp.path().join("key2.json")));

    // Create the vault; logging in needs the key, and short drive PINs are refused.
    const USER: &str = "amber-falcon-orchard";
    assert!(create_vault(&url, USER, Some("wrong".into()), key.clone())
        .await
        .is_err());
    create_vault(&url, USER, Some("letmein".into()), key.clone())
        .await
        .unwrap();
    assert!(matches!(
        create_vault(&url, USER, Some("letmein".into()), key.clone()).await,
        Err(Error::Api { status: 409, .. })
    ));
    assert!(connect(&url, USER, key.clone(), 0, "1234").await.is_err());

    // The same key also holds a second, unrelated username (its own vault).
    create_vault(
        &url,
        "second-identity-xyz",
        Some("letmein".into()),
        key.clone(),
    )
    .await
    .unwrap();
    let (other, k) = connect(&url, "second-identity-xyz", key.clone(), 0, "22222222")
        .await
        .unwrap();
    other.create(&k).await.unwrap();

    // Unknown usernames get a stable decoy record, so the server reveals nothing.
    let anon = strongbox_client::api::Api::new(&url).unwrap();
    let decoy1 = anon.vault_record(&[7u8; 32]).await.unwrap();
    assert_eq!(decoy1, anon.vault_record(&[7u8; 32]).await.unwrap());
    assert_eq!(decoy1.len(), strongbox_core::vault::RECORD_LEN);
    assert!(matches!(
        connect(&url, "no-such-user", key.clone(), 0, "11111111").await,
        Err(Error::Invalid(_))
    ));

    // A slot nobody used and a wrong PIN look exactly the same: no drive.
    let (vault, decoy_key) = connect(&url, USER, key.clone(), 0, "11111111")
        .await
        .unwrap();
    assert!(vault.open(&decoy_key).await.unwrap().is_none());

    // Decoy drive in slot 0, hidden drive in slot 2.
    let mut decoy = vault.create(&decoy_key).await.unwrap();
    std::fs::write(local.join("shopping.txt"), b"milk, eggs").unwrap();
    decoy
        .upload(&local.join("shopping.txt"), "/", TransferOptions::default())
        .await
        .unwrap();

    let hidden_key = vault
        .slot_key(key.clone(), 2, "secret-drive-pin")
        .await
        .unwrap();
    let mut hidden = vault.create(&hidden_key).await.unwrap();
    hidden.mkdir("/Evidence").await.unwrap();
    let big: Vec<u8> = (0..700_000u32)
        .map(|i| (i.wrapping_mul(2654435761) >> 11) as u8)
        .collect();
    std::fs::write(local.join("WHISTLEBLOWER-dossier.pdf"), &big).unwrap();
    hidden
        .upload(
            &local.join("WHISTLEBLOWER-dossier.pdf"),
            "/Evidence",
            TransferOptions::default(),
        )
        .await
        .unwrap();
    let keep = TransferOptions {
        on_conflict: OnConflict::KeepBoth,
        ..Default::default()
    };
    assert_eq!(
        hidden
            .upload(&local.join("WHISTLEBLOWER-dossier.pdf"), "/Evidence", keep)
            .await
            .unwrap(),
        "WHISTLEBLOWER-dossier (1).pdf"
    );
    hidden
        .remove("/Evidence/WHISTLEBLOWER-dossier (1).pdf")
        .await
        .unwrap();
    let code = hidden.new_recovery_code().await.unwrap();
    hidden
        .add_key(backup.clone(), "secret-drive-pin")
        .await
        .unwrap();
    assert!(
        hidden
            .add_key(backup.clone(), "secret-drive-pin")
            .await
            .is_err(),
        "already added"
    );
    drop(hidden);

    // Reopen in a fresh session: one touch logs in and opens the drive.
    let (vault2, k) = connect(&url, USER, key.clone(), 2, "secret-drive-pin")
        .await
        .unwrap();
    let hidden = vault2
        .open(&k)
        .await
        .unwrap()
        .expect("hidden drive opens with its PIN");
    assert_eq!(
        hidden
            .list("/Evidence")
            .unwrap()
            .iter()
            .map(|e| e.name.as_str())
            .collect::<Vec<_>>(),
        ["WHISTLEBLOWER-dossier.pdf"]
    );
    hidden
        .download(
            "/Evidence/WHISTLEBLOWER-dossier.pdf",
            &local.join("out.pdf"),
            TransferOptions::default(),
        )
        .await
        .unwrap();
    assert_eq!(std::fs::read(local.join("out.pdf")).unwrap(), big);

    // Wrong PIN on the hidden slot, and the never-used slots: indistinguishable "nothing".
    for (slot, pin) in [
        (2, "wrong-pin-123"),
        (1, "secret-drive-pin"),
        (3, "11111111"),
    ] {
        let k = vault2.slot_key(key.clone(), slot, pin).await.unwrap();
        assert!(vault2.open(&k).await.unwrap().is_none(), "slot {slot}");
    }

    // The backup key opens it too; so does the recovery code (which finds the slot itself).
    let (v3, k3) = connect(&url, USER, backup.clone(), 2, "secret-drive-pin")
        .await
        .unwrap();
    assert!(v3.open(&k3).await.unwrap().is_some());
    let (v4, k4) = connect_with_recovery(&url, USER, &code).await.unwrap();
    assert_eq!(k4.slot(), 2);
    assert!(v4.open(&k4).await.unwrap().is_some());
    assert!(
        v4.create(&k4).await.is_err(),
        "recovery codes cannot create drives"
    );
    let (members, _) = v4.members().await.unwrap();
    assert_eq!(members.len(), 3, "key, backup key, recovery code");

    // Seized-server view: every slot file has the same size, no plaintext, no names, and
    // identical timestamps whether or not the slot holds a drive.
    let files = vault_files(&server_dir);
    assert_eq!(files.len(), 2 * SLOTS as usize, "two usernames, two vaults");
    let meta: Vec<_> = files
        .iter()
        .map(|f| std::fs::metadata(f).unwrap())
        .collect();
    assert!(meta
        .iter()
        .all(|m| m.len() == meta[0].len() && m.modified().unwrap() == meta[0].modified().unwrap()));
    let mut all = Vec::new();
    for f in &files {
        all.extend(std::fs::read(f).unwrap());
    }
    for needle in [
        &b"WHISTLEBLOWER"[..],
        b"Evidence",
        b"shopping",
        b"milk, eggs",
        &big[5000..5032],
    ] {
        assert!(
            !contains(&all, needle),
            "plaintext {:?} on the server",
            String::from_utf8_lossy(needle)
        );
    }
    let db = std::fs::read(server_dir.join("strongbox.sqlite3")).unwrap();
    for needle in [
        &b"WHISTLEBLOWER"[..],
        b"Evidence",
        USER.as_bytes(),
        b"second-identity-xyz",
        b"Strongbox",
    ] {
        assert!(
            !contains(&db, needle),
            "{:?} in the database",
            String::from_utf8_lossy(needle)
        );
    }

    // Resetting a slot destroys the drive (with that PIN or any other).
    let k = vault2.slot_key(key.clone(), 0, "11111111").await.unwrap();
    vault2.create(&k).await.unwrap();
    let decoy_again = vault2.open(&k).await.unwrap().unwrap();
    assert!(decoy_again.list("/").unwrap().is_empty());

    // A key that is not one of this username's keys cannot log in.
    let stranger: Arc<dyn Authenticator> =
        Arc::new(SoftAuthenticator::new(tmp.path().join("key3.json")));
    stranger.enroll("strongbox.app", "x", &[]).unwrap();
    assert!(connect(&url, USER, stranger, 0, "11111111").await.is_err());

    // Helpers the desktop app uses: nested folders, in-memory list/search, folder download, wipe.
    let k = vault2
        .slot_key(key.clone(), 2, "secret-drive-pin")
        .await
        .unwrap();
    let mut h = vault2.open(&k).await.unwrap().unwrap();
    h.mkdir_p("/a/b/c").await.unwrap();
    h.mkdir_p("/a/b").await.unwrap();
    assert_eq!(
        strongbox_client::vault::list_in(h.tree(), "/a/b").unwrap()[0].name,
        "c"
    );
    assert_eq!(
        strongbox_client::vault::search_in(h.tree(), "DOSSIER").len(),
        1
    );
    let out = h
        .download_dir("/Evidence", &local, TransferOptions::default())
        .await
        .unwrap();
    assert_eq!(
        std::fs::read(out.join("WHISTLEBLOWER-dossier.pdf")).unwrap(),
        big
    );
    h.wipe();
    assert!(h.mkdir("/after-wipe").await.is_err());
    assert!(h
        .read_file("/Evidence/WHISTLEBLOWER-dossier.pdf", 1 << 30)
        .await
        .is_err());

    // Drives fill up cleanly.
    let mut d = decoy_again;
    let huge = vec![1u8; (BLOCKS as usize) * 256 * 1024];
    std::fs::write(local.join("huge.bin"), &huge).unwrap();
    assert!(d
        .upload(&local.join("huge.bin"), "/", TransferOptions::default())
        .await
        .is_err());
    assert!(d.list("/").unwrap().is_empty());
}

#[tokio::test(flavor = "multi_thread")]
async fn delete_account_removes_everything() {
    let tmp = tempfile::tempdir().unwrap();
    let server_dir = tmp.path().join("server");
    let url = start_server(&server_dir).await;
    let key: Arc<dyn Authenticator> =
        Arc::new(SoftAuthenticator::new(tmp.path().join("key1.json")));
    const USER: &str = "doomed-account-name";

    let account = create_vault(&url, USER, Some("letmein".into()), key.clone())
        .await
        .unwrap();
    let (client, k) = connect(&url, USER, key.clone(), 0, "12345678")
        .await
        .unwrap();
    client.create(&k).await.unwrap();
    client.delete_account().await.unwrap();

    // The session is gone, and so is the account: it can't sign in or be created over again.
    assert!(account.members().await.is_err());
    assert!(connect_account(&url, USER, key.clone()).await.is_err());
    assert!(connect(&url, USER, key.clone(), 0, "12345678")
        .await
        .is_err());
    assert!(std::fs::read_dir(server_dir.join("vaults"))
        .map(|mut d| d.next().is_none())
        .unwrap_or(true));
}

#[tokio::test(flavor = "multi_thread")]
async fn missing_vault_storage_is_a_clean_error() {
    let tmp = tempfile::tempdir().unwrap();
    let server_dir = tmp.path().join("server");
    let url = start_server(&server_dir).await;
    let key: Arc<dyn Authenticator> =
        Arc::new(SoftAuthenticator::new(tmp.path().join("key1.json")));
    const USER: &str = "orphaned-account-name";

    create_vault(&url, USER, Some("letmein".into()), key.clone())
        .await
        .unwrap();
    // The operator deletes the vault files (to reclaim disk space) but not the database.
    for entry in std::fs::read_dir(server_dir.join("vaults")).unwrap() {
        std::fs::remove_dir_all(entry.unwrap().path()).unwrap();
    }

    // Signing in still works; opening a drive says the storage is missing instead of a 500.
    let (client, k) = connect(&url, USER, key.clone(), 0, "12345678")
        .await
        .unwrap();
    match client.open(&k).await {
        Err(Error::Api {
            status: 404,
            message,
            ..
        }) => assert!(message.contains("storage"), "{message}"),
        other => panic!("expected a 404, got {:?}", other.map(|_| ())),
    }
    assert!(matches!(
        client.create(&k).await,
        Err(Error::Api { status: 404, .. })
    ));
    // The account can still be deleted, so its owner can start over with the same username.
    client.delete_account().await.unwrap();
    create_vault(&url, USER, Some("letmein".into()), key.clone())
        .await
        .unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn change_pin_and_rename_keys() {
    let tmp = tempfile::tempdir().unwrap();
    let url = start_server(&tmp.path().join("server")).await;
    let key: Arc<dyn Authenticator> =
        Arc::new(SoftAuthenticator::new(tmp.path().join("key1.json")));
    let backup: Arc<dyn Authenticator> =
        Arc::new(SoftAuthenticator::new(tmp.path().join("key2.json")));
    const USER: &str = "pin-change-user";
    const OLD: &str = "old-drive-pin";
    const NEW: &str = "new-drive-pin";
    create_vault(&url, USER, Some("letmein".into()), key.clone())
        .await
        .unwrap();
    let (vault, k) = connect(&url, USER, key.clone(), 1, OLD).await.unwrap();
    let mut drive = vault.create(&k).await.unwrap();
    drive.mkdir("/kept").await.unwrap();
    let code = drive.new_recovery_code().await.unwrap();
    drive
        .add_key_named(backup.clone(), OLD, "Backup")
        .await
        .unwrap();

    // The PIN must be a valid one, and a recovery-code session cannot change it.
    assert!(drive.change_pin(key.clone(), "short").await.is_err());
    let (rv, rk) = connect_with_recovery(&url, USER, &code).await.unwrap();
    let mut by_code = rv.open(&rk).await.unwrap().unwrap();
    assert!(by_code.change_pin(key.clone(), NEW).await.is_err());

    // The key that opened the drive changes the PIN; the backup key (old PIN) loses access.
    assert_eq!(drive.change_pin(key.clone(), NEW).await.unwrap(), 1);
    let (v2, k2) = connect(&url, USER, key.clone(), 1, NEW).await.unwrap();
    let d2 = v2.open(&k2).await.unwrap().expect("opens with the new PIN");
    assert_eq!(d2.list("/").unwrap()[0].name, "kept");
    let old = v2.slot_key(key.clone(), 1, OLD).await.unwrap();
    assert!(v2.open(&old).await.unwrap().is_none(), "old PIN is dead");
    let stale = v2.slot_key(backup.clone(), 1, OLD).await.unwrap();
    assert!(
        v2.open(&stale).await.unwrap().is_none(),
        "backup key lost access"
    );
    let fresh = v2.slot_key(backup.clone(), 1, NEW).await.unwrap();
    assert!(
        v2.open(&fresh).await.unwrap().is_none(),
        "backup was not re-granted"
    );
    // The recovery code still opens it.
    let (rv, rk) = connect_with_recovery(&url, USER, &code).await.unwrap();
    assert!(rv.open(&rk).await.unwrap().is_some());

    // Keys and recovery codes can be renamed; the new names survive a fresh login.
    let labels = v2.member_labels();
    let backup_id = labels
        .iter()
        .find(|m| m.label == "Backup")
        .unwrap()
        .id
        .clone();
    v2.rename_member(&backup_id, "  Safe deposit key ")
        .await
        .unwrap();
    assert!(v2.rename_member(&backup_id, "   ").await.is_err());
    assert!(v2.rename_member(&backup_id, &"x".repeat(81)).await.is_err());
    assert!(v2.rename_member("nope", "x").await.is_err());
    let (v3, _) = connect(&url, USER, key.clone(), 1, NEW).await.unwrap();
    assert!(v3
        .member_labels()
        .iter()
        .any(|m| m.id == backup_id && m.label == "Safe deposit key"));
}

#[tokio::test(flavor = "multi_thread")]
async fn key_and_recovery_names_are_unique() {
    let tmp = tempfile::tempdir().unwrap();
    let url = start_server(&tmp.path().join("server")).await;
    let key: Arc<dyn Authenticator> =
        Arc::new(SoftAuthenticator::new(tmp.path().join("key1.json")));
    let backup: Arc<dyn Authenticator> =
        Arc::new(SoftAuthenticator::new(tmp.path().join("key2.json")));
    const USER: &str = "unique-names-user";
    create_vault(&url, USER, Some("letmein".into()), key.clone())
        .await
        .unwrap();
    let (vault, k) = connect(&url, USER, key.clone(), 0, "drive-pin-0")
        .await
        .unwrap();
    let mut drive = vault.create(&k).await.unwrap();

    // The first key is "Security key 1", so the next suggestion is "Security key 2".
    assert_eq!(vault.suggest_label("Security key 1", &[]), "Security key 2");
    assert_eq!(vault.suggest_label("Backup key", &[]), "Backup key");
    drive
        .new_recovery_code_named("Recovery code")
        .await
        .unwrap();
    assert_eq!(vault.suggest_label("Recovery code", &[]), "Recovery code 2");
    // Replacing this drive's code may reuse its name.
    assert_eq!(
        vault.suggest_label("Recovery code", &drive.recovery_ids()),
        "Recovery code"
    );
    drive
        .new_recovery_code_named("Recovery code")
        .await
        .unwrap();

    // Duplicates (ignoring case and spaces) are refused for keys, recovery codes and renames,
    // before any key is touched.
    for name in ["Security key 1", "  security KEY 1 ", "recovery code"] {
        assert!(drive
            .add_key_named(backup.clone(), "drive-pin-0", name)
            .await
            .is_err());
        assert!(vault
            .add_account_key_named(backup.clone(), name)
            .await
            .is_err());
        assert!(vault.new_account_recovery_code_named(name).await.is_err());
        assert!(drive
            .new_recovery_code_named("Security key 1")
            .await
            .is_err());
    }
    drive
        .add_key_named(backup.clone(), "drive-pin-0", "Security key 2")
        .await
        .unwrap();
    let ids: Vec<_> = vault.member_labels().into_iter().map(|m| m.id).collect();
    assert!(vault
        .rename_member(&ids[0], "security key 2")
        .await
        .is_err());
    vault
        .rename_member(&ids[0], "SECURITY KEY 1")
        .await
        .unwrap(); // own name, new case
    assert_eq!(vault.member_labels().len(), 3);
}

#[tokio::test(flavor = "multi_thread")]
async fn invite_codes_and_admin_page() {
    let tmp = tempfile::tempdir().unwrap();
    let (url, admin_url) = start_server_with_admin(&tmp.path().join("server")).await;
    let key: Arc<dyn Authenticator> =
        Arc::new(SoftAuthenticator::new(tmp.path().join("key1.json")));
    let http = reqwest::Client::new();
    let admin = |m: reqwest::Method, path: &str| {
        http.request(m, format!("{admin_url}{path}"))
            .header("x-strongbox-admin", "1")
    };

    // The service port does not serve the admin page at all.
    assert_eq!(
        http.get(format!("{url}/admin/stats"))
            .send()
            .await
            .unwrap()
            .status(),
        404
    );

    // The page and API are served to a direct local browser...
    let page = http.get(format!("{admin_url}/")).send().await.unwrap();
    assert_eq!(page.status(), 200);
    assert!(page.text().await.unwrap().contains("Invite codes"));

    // ...but not through a proxy (forwarded headers), under a foreign Host, or without the
    // custom header on a change.
    let proxied = http
        .get(format!("{admin_url}/admin/stats"))
        .header("x-forwarded-for", "203.0.113.9")
        .send()
        .await
        .unwrap();
    assert_eq!(proxied.status(), 404);
    let rebound = http
        .get(format!("{admin_url}/admin/stats"))
        .header("host", "evil.example")
        .send()
        .await
        .unwrap();
    assert_eq!(rebound.status(), 404);
    let no_header = http
        .post(format!("{admin_url}/admin/codes"))
        .json(&serde_json::json!({ "single_use": true }))
        .send()
        .await
        .unwrap();
    assert_eq!(no_header.status(), 404);

    // A single-use code admits exactly one account and then disappears from the list.
    let once: serde_json::Value = admin(reqwest::Method::POST, "/admin/codes")
        .json(&serde_json::json!({ "single_use": true }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let once_code = once["code"].as_str().unwrap().to_string();
    create_vault(&url, "first-user-abc", Some(once_code.clone()), key.clone())
        .await
        .unwrap();
    assert!(matches!(
        create_vault(&url, "second-user-abc", Some(once_code), key.clone()).await,
        Err(Error::Api { status: 403, .. })
    ));
    let codes: serde_json::Value = admin(reqwest::Method::GET, "/admin/codes")
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(codes.as_array().unwrap().is_empty());

    // A failed creation (username taken) does not spend the code.
    let again: serde_json::Value = admin(reqwest::Method::POST, "/admin/codes")
        .json(&serde_json::json!({ "single_use": true }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let again_code = again["code"].as_str().unwrap().to_string();
    assert!(matches!(
        create_vault(
            &url,
            "first-user-abc",
            Some(again_code.clone()),
            key.clone()
        )
        .await,
        Err(Error::Api { status: 409, .. })
    ));
    create_vault(&url, "third-user-abc", Some(again_code), key.clone())
        .await
        .unwrap();

    // Standard codes keep working until deleted.
    let std: serde_json::Value = admin(reqwest::Method::POST, "/admin/codes")
        .json(&serde_json::json!({ "single_use": false, "code": "friends-2026" }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    for name in ["std-user-one-x", "std-user-two-x"] {
        create_vault(&url, name, Some("friends-2026".into()), key.clone())
            .await
            .unwrap();
    }
    let del = admin(
        reqwest::Method::DELETE,
        &format!("/admin/codes/{}", std["id"]),
    )
    .send()
    .await
    .unwrap();
    assert_eq!(del.status(), 204);
    assert!(matches!(
        create_vault(
            &url,
            "std-user-three",
            Some("friends-2026".into()),
            key.clone()
        )
        .await,
        Err(Error::Api { status: 403, .. })
    ));

    // Stats count accounts and allocated storage.
    let stats: serde_json::Value = admin(reqwest::Method::GET, "/admin/stats")
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(stats["accounts"], 4);
    assert_eq!(
        stats["allocated_bytes"],
        4 * SLOTS as u64 * BLOCKS as u64 * 262_144
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn pipelined_transfers_and_batched_commits() {
    let tmp = tempfile::tempdir().unwrap();
    let local = tmp.path().join("local");
    std::fs::create_dir_all(&local).unwrap();
    // Drives big enough for a file spanning more requests than are kept in flight.
    let (url, _) = start_server_sized(&tmp.path().join("server"), 2, 120).await;
    let key: Arc<dyn Authenticator> = Arc::new(SoftAuthenticator::new(tmp.path().join("key.json")));
    const USER: &str = "pipeline-test-user";
    create_vault(&url, USER, Some("letmein".into()), key.clone())
        .await
        .unwrap();
    let (vault, k) = connect(&url, USER, key.clone(), 1, "31415926")
        .await
        .unwrap();
    let mut d = vault.create(&k).await.unwrap();

    let payload = strongbox_core::vault::BLOCK_PAYLOAD;
    let big: Vec<u8> = (0..(3 * 32 + 5) * payload as u32 + 1234)
        .map(|i| (i.wrapping_mul(2654435761) >> 13) as u8)
        .collect();
    std::fs::write(local.join("big.bin"), &big).unwrap();
    let seen = std::sync::Mutex::new(Vec::new());
    let progress = |done: u64, total: u64| seen.lock().unwrap().push((done, total));
    let opts = TransferOptions {
        progress: Some(&progress),
        ..Default::default()
    };
    d.upload(&local.join("big.bin"), "/", opts).await.unwrap();
    {
        let seen = seen.lock().unwrap();
        assert!(
            seen.windows(2).all(|w| w[0].0 <= w[1].0),
            "progress only grows"
        );
        assert_eq!(seen.last(), Some(&(big.len() as u64, big.len() as u64)));
    }
    seen.lock().unwrap().clear();
    d.download("/big.bin", &local.join("back.bin"), opts)
        .await
        .unwrap();
    assert!(std::fs::read(local.join("back.bin")).unwrap() == big);
    assert!(seen.lock().unwrap().windows(2).all(|w| w[0].0 <= w[1].0));

    // A batch: folders and files appear together, in one commit, and persist.
    let mut staged = d.stage();
    d.mkdir_p_staged(&mut staged, "/a/b").unwrap();
    for i in 0..3 {
        let f = local.join(format!("f{i}.txt"));
        std::fs::write(&f, format!("file {i}")).unwrap();
        d.upload_staged(&mut staged, &f, "/a/b", TransferOptions::default())
            .await
            .unwrap();
    }
    assert!(d.list("/a").is_err(), "nothing visible before the commit");
    assert!(!d.staged_due(&staged));
    d.commit_staged(&mut staged).await.unwrap();
    assert_eq!(d.list("/a/b").unwrap().len(), 3);
    let again = vault.open(&k).await.unwrap().unwrap();
    assert_eq!(
        again.read_file("/a/b/f1.txt", 100).await.unwrap(),
        b"file 1"
    );
    drop(again);

    // Replacing a committed file makes the batch due at once (its old key is wiped promptly).
    std::fs::write(local.join("f0.txt"), b"new content").unwrap();
    d.upload_staged(
        &mut staged,
        &local.join("f0.txt"),
        "/a/b",
        TransferOptions::default(),
    )
    .await
    .unwrap();
    assert!(d.staged_due(&staged));
    d.commit_staged(&mut staged).await.unwrap();
    assert_eq!(
        d.read_file("/a/b/f0.txt", 100).await.unwrap(),
        b"new content"
    );

    // A change made outside the batch is never undone by committing a stale batch.
    let mut staged = d.stage();
    d.upload_staged(
        &mut staged,
        &local.join("f2.txt"),
        "/",
        TransferOptions::default(),
    )
    .await
    .unwrap();
    d.mkdir("/outside").await.unwrap();
    assert!(d.commit_staged(&mut staged).await.is_err());
    assert!(d.list("/outside").is_ok());
    assert!(d.list("/").unwrap().iter().all(|e| e.name != "f2.txt"));
    // The batch restarted from the current drive, so it is usable again.
    d.upload_staged(
        &mut staged,
        &local.join("f2.txt"),
        "/",
        TransferOptions::default(),
    )
    .await
    .unwrap();
    d.commit_staged(&mut staged).await.unwrap();
    assert!(d.list("/outside").is_ok());
    assert_eq!(d.read_file("/f2.txt", 100).await.unwrap(), b"file 2");
    assert!(std::fs::read(local.join("back.bin")).unwrap() == big);
    d.download(
        "/big.bin",
        &local.join("back2.bin"),
        TransferOptions::default(),
    )
    .await
    .unwrap();
    assert!(std::fs::read(local.join("back2.bin")).unwrap() == big);
}
