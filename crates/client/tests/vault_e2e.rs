//! Deniable vaults end to end (docs/deniable-drives.md) with the software authenticator.

use std::path::Path;
use std::sync::Arc;

use strongbox_client::vault::{connect, connect_with_recovery, create_vault};
use strongbox_client::{Error, OnConflict, TransferOptions};
use strongbox_fido::soft::SoftAuthenticator;
use strongbox_fido::Authenticator;
use strongbox_proto::RegistrationMode;
use strongbox_server::Config;

const SLOTS: u32 = 4;
const BLOCKS: u32 = 16;

async fn start_server(data_dir: &Path) -> String {
    let config = Config {
        listen: "127.0.0.1:0".parse().unwrap(),
        data_dir: data_dir.to_path_buf(),
        registration: RegistrationMode::Invite,
        invite_token: Some("letmein".into()),
        quota_bytes: None,
        session_ttl_secs: 3600,
        prelogin_rate_per_minute: 1000,
        trust_proxy: false,
        debug: false,
        vault_slots: Some(SLOTS),
        vault_slot_blocks: Some(BLOCKS),
        drive_size: None,
        max_blob_size: 8 * 1024 * 1024,
        max_node_size: 16 * 1024 * 1024,
    };
    let app = strongbox_server::build(config).await.unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(
            listener,
            app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
        )
        .await
        .unwrap()
    });
    format!("http://{addr}")
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
