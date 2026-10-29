//! Full client <-> server round trip using the software authenticator.

use std::path::Path;
use std::sync::Arc;

use strongbox_client::api::Api;
use strongbox_client::{
    login, login_with_recovery, register, sign_in, Drive, Error, OnConflict, Profile,
    RegisterOptions, TransferOptions, Ui, TRASH_NAME,
};
use strongbox_core::Id;
use strongbox_fido::soft::SoftAuthenticator;
use strongbox_fido::{Authenticator, Interaction};
use strongbox_proto::RegistrationMode;
use strongbox_server::Config;

struct TestUi;

impl Interaction for TestUi {
    fn status(&self, _: &str) {}
    fn request_pin(&self, _: Option<u8>) -> Option<String> {
        None
    }
}

impl Ui for TestUi {
    fn request_password(&self) -> Option<String> {
        None
    }
}

async fn start_server(data_dir: &Path) -> String {
    let config = Config {
        listen: "127.0.0.1:0".parse().unwrap(),
        data_dir: data_dir.to_path_buf(),
        registration: RegistrationMode::Invite,
        invite_token: Some("letmein".into()),
        quota_bytes: Some(1 << 30),
        session_ttl_secs: 3600,
        prelogin_rate_per_minute: 1000,
        trust_proxy: false,
        debug: false,
        vault_slots: Some(4),
        vault_slot_blocks: Some(16),
        drive_size: None,
        max_blob_size: 8 * 1024 * 1024,
        max_node_size: 16 * 1024 * 1024,
    };
    let app = strongbox_server::build(config).await.unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum_serve(listener, app).await });
    format!("http://{addr}")
}

async fn axum_serve(listener: tokio::net::TcpListener, app: axum::Router) {
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
    )
    .await
    .unwrap();
}

/// Every file the server persisted, concatenated.
fn server_bytes(dir: &Path) -> Vec<u8> {
    let mut out = Vec::new();
    let mut stack = vec![dir.to_path_buf()];
    while let Some(d) = stack.pop() {
        for e in std::fs::read_dir(d).unwrap() {
            let p = e.unwrap().path();
            if p.is_dir() {
                stack.push(p);
            } else {
                out.extend(std::fs::read(&p).unwrap());
            }
        }
    }
    out
}

fn contains(hay: &[u8], needle: &[u8]) -> bool {
    hay.windows(needle.len()).any(|w| w == needle)
}

async fn unlock(authn: &Arc<dyn Authenticator>) -> Drive {
    login(
        Profile::load().unwrap().unwrap(),
        authn.clone(),
        Arc::new(TestUi),
    )
    .await
    .unwrap()
}

#[tokio::test(flavor = "multi_thread")]
async fn end_to_end() {
    let tmp = tempfile::tempdir().unwrap();
    let server_dir = tmp.path().join("server");
    let local = tmp.path().join("local");
    std::fs::create_dir_all(&local).unwrap();
    std::env::set_var("STRONGBOX_CONFIG_DIR", tmp.path().join("config"));
    let url = start_server(&server_dir).await;

    let key1: Arc<dyn Authenticator> =
        Arc::new(SoftAuthenticator::new(tmp.path().join("key1.json")));
    let key2: Arc<dyn Authenticator> =
        Arc::new(SoftAuthenticator::new(tmp.path().join("key2.json")));

    // Registration requires the invite token.
    let opts = |invite: &str| RegisterOptions {
        server_url: url.clone(),
        username: "alice".into(),
        invite: Some(invite.into()),
        key_label: "key one".into(),
        password: None,
        recovery_code: true,
        rp_id: None,
    };
    assert!(register(opts("wrong"), key1.clone()).await.is_err());
    let (drive, code) = register(opts("letmein"), key1.clone()).await.unwrap();
    let code = code.unwrap();

    // Upload a multi-chunk file and a small one with a distinctive name and content.
    let big: Vec<u8> = (0..9_500_000u32)
        .map(|i| (i.wrapping_mul(2654435761) >> 13) as u8)
        .collect();
    std::fs::write(local.join("holiday-video.bin"), &big).unwrap();
    std::fs::write(
        local.join("TOP-SECRET-plans.txt"),
        b"MEET AT THE OLD MILL AT MIDNIGHT",
    )
    .unwrap();
    drive.mkdir("/Documents").await.unwrap();
    assert!(matches!(
        drive.mkdir("/Documents").await,
        Err(Error::Exists(_))
    ));
    drive
        .upload(&local.join("TOP-SECRET-plans.txt"), "/Documents", None)
        .await
        .unwrap();
    drive
        .upload(&local.join("holiday-video.bin"), "/", None)
        .await
        .unwrap();

    let root = drive.list("/").await.unwrap();
    assert_eq!(
        root.iter().map(|e| e.name.as_str()).collect::<Vec<_>>(),
        ["Documents", "holiday-video.bin"]
    );
    assert_eq!(root[1].size, big.len() as u64);

    // The server must not hold names, contents or exact sizes in plaintext.
    let stored = server_bytes(&server_dir);
    for needle in [
        &b"TOP-SECRET"[..],
        b"holiday-video",
        b"Documents",
        b"OLD MILL",
        &big[1000..1032],
    ] {
        assert!(
            !contains(&stored, needle),
            "server stored plaintext {:?}",
            String::from_utf8_lossy(needle)
        );
    }
    let usage = drive.usage().await.unwrap();
    assert!(usage.used_bytes > big.len() as u64, "padded + tags");

    // Download and compare.
    drive
        .download("/holiday-video.bin", &local.join("out.bin"), None)
        .await
        .unwrap();
    assert_eq!(std::fs::read(local.join("out.bin")).unwrap(), big);

    // Replacing a file frees the old chunks.
    std::fs::write(local.join("holiday-video.bin"), b"short now").unwrap();
    drive
        .upload(&local.join("holiday-video.bin"), "/", None)
        .await
        .unwrap();
    assert!(drive.usage().await.unwrap().used_bytes < usage.used_bytes / 2);

    // Concurrent writers to the same directory both succeed (conflict -> retry).
    let other = unlock(&key1).await;
    for i in 0..4 {
        std::fs::write(local.join(format!("c{i}.txt")), format!("{i}")).unwrap();
    }
    let (a, b) = tokio::join!(
        async {
            drive
                .upload(&local.join("c0.txt"), "/Documents", None)
                .await?;
            drive
                .upload(&local.join("c1.txt"), "/Documents", None)
                .await
        },
        async {
            other
                .upload(&local.join("c2.txt"), "/Documents", None)
                .await?;
            other
                .upload(&local.join("c3.txt"), "/Documents", None)
                .await
        }
    );
    a.unwrap();
    b.unwrap();
    assert_eq!(drive.list("/Documents").await.unwrap().len(), 5);

    // Rename and move.
    drive.mkdir("/Archive").await.unwrap();
    drive
        .rename("/Documents/c0.txt", "/Archive/zero.txt")
        .await
        .unwrap();
    drive.rename("/Archive", "/Old").await.unwrap();
    assert!(drive.rename("/Old", "/Old/inner").await.is_err());
    drive
        .download("/Old/zero.txt", &local.join("zero.txt"), None)
        .await
        .unwrap();
    assert_eq!(std::fs::read(local.join("zero.txt")).unwrap(), b"0");

    // Recursive delete frees everything underneath.
    drive.remove("/Documents").await.unwrap();
    assert!(drive.list("/Documents").await.unwrap_err().is_not_found());

    // A second key unlocks the same drive; the last keyslot cannot be removed.
    drive
        .add_security_key(key2.clone(), "key two".into(), None)
        .await
        .unwrap();
    let via_key2 = unlock(&key2).await;
    assert_eq!(via_key2.list("/Old").await.unwrap()[0].name, "zero.txt");
    assert_eq!(drive.keyslots().await.unwrap().len(), 3);

    // Recovery code unlocks too; a wrong one does not.
    let profile = Profile::load().unwrap().unwrap();
    assert!(login_with_recovery(profile.clone(), &code).await.is_ok());
    let mut wrong = code.clone();
    wrong.replace_range(0..1, if wrong.starts_with('A') { "B" } else { "A" });
    assert!(login_with_recovery(profile, &wrong).await.is_err());

    // An unknown key cannot unlock.
    let stranger: Arc<dyn Authenticator> =
        Arc::new(SoftAuthenticator::new(tmp.path().join("key3.json")));
    stranger.enroll("strongbox.app", "x", &[]).unwrap();
    assert!(login(
        Profile::load().unwrap().unwrap(),
        stranger,
        Arc::new(TestUi)
    )
    .await
    .is_err());

    // Orphan cleanup finds nothing after clean operations.
    assert_eq!(drive.collect_garbage().await.unwrap(), 0);

    // Keep-both uploads, search, trash and restore.
    std::fs::write(local.join("notes.txt"), b"v1").unwrap();
    assert_eq!(
        drive
            .upload(&local.join("notes.txt"), "/Old", None)
            .await
            .unwrap(),
        "notes.txt"
    );
    let keep_both = TransferOptions {
        on_conflict: OnConflict::KeepBoth,
        ..Default::default()
    };
    assert_eq!(
        drive
            .upload_with(&local.join("notes.txt"), "/Old", keep_both)
            .await
            .unwrap(),
        "notes (1).txt"
    );
    let fail = TransferOptions {
        on_conflict: OnConflict::Fail,
        ..Default::default()
    };
    assert!(matches!(
        drive
            .upload_with(&local.join("notes.txt"), "/Old", fail)
            .await,
        Err(Error::Exists(_))
    ));
    let hits = drive.search("NOTES").await.unwrap();
    assert_eq!(
        hits.iter().map(|h| h.path.as_str()).collect::<Vec<_>>(),
        ["/Old/notes (1).txt", "/Old/notes.txt"]
    );
    assert_eq!(
        drive.read_file("/Old/notes.txt", 1024).await.unwrap(),
        b"v1"
    );

    let before = drive.usage().await.unwrap().used_bytes;
    let trash_id = drive.trash("/Old").await.unwrap();
    assert!(drive
        .list("/")
        .await
        .unwrap()
        .iter()
        .all(|e| e.name != "Old" && e.name != TRASH_NAME));
    assert!(
        drive.list(&format!("/{TRASH_NAME}")).await.is_err(),
        "trash is not addressable by path"
    );
    assert!(
        drive.search("notes").await.unwrap().is_empty(),
        "search skips the trash"
    );
    let trash = drive.list_trash().await.unwrap();
    assert_eq!(
        (
            trash.len(),
            trash[0].name.as_str(),
            trash[0].parent.as_str()
        ),
        (1, "Old", "/")
    );
    assert_eq!(trash[0].id, trash_id);
    drive.mkdir("/Old").await.unwrap(); // the name is taken again, so restore must rename
    assert_eq!(drive.restore(&trash[0].id).await.unwrap(), "/Old (1)");
    assert_eq!(drive.list("/Old (1)").await.unwrap().len(), 3);
    drive.trash("/Old (1)/notes.txt").await.unwrap();
    assert_eq!(drive.empty_trash().await.unwrap(), 1);
    assert!(drive.usage().await.unwrap().used_bytes < before);
    assert_eq!(drive.collect_garbage().await.unwrap(), 0);

    // Panic wipe: the keys go at once, even through a shared handle, and nothing works after.
    let shared = Arc::new(unlock(&key1).await);
    let other_handle = shared.clone();
    assert!(!shared.list("/").await.unwrap().is_empty());
    shared.wipe();
    assert!(other_handle.is_wiped());
    assert!(other_handle.list("/").await.is_err());
    assert!(other_handle.mkdir("/after-wipe").await.is_err());
    assert!(other_handle.add_recovery_code().await.is_err());
    other_handle.end_session().await.unwrap();

    // A second device signs in with only the server URL and username.
    std::env::set_var("STRONGBOX_CONFIG_DIR", tmp.path().join("config2"));
    assert!(Profile::load().unwrap().is_none());
    let second = sign_in(&url, "alice", None, key2.clone(), Arc::new(TestUi))
        .await
        .unwrap();
    assert!(second
        .list("/")
        .await
        .unwrap()
        .iter()
        .any(|e| e.name == "Old (1)"));
    assert_eq!(Profile::load().unwrap().unwrap().username, "alice");
    // A failed sign-in does not overwrite the saved profile.
    assert!(
        sign_in(&url, "mallory", None, key2.clone(), Arc::new(TestUi))
            .await
            .is_err()
    );
    assert_eq!(Profile::load().unwrap().unwrap().username, "alice");

    // Unknown usernames get stable decoy keyslots instead of a 404 (no enumeration), and
    // nothing is readable without a session.
    let anon = Api::new(&url).unwrap();
    let decoy = anon.keyslots("nobody-here").await.unwrap();
    assert_eq!(decoy.len(), 2);
    assert_eq!(decoy, anon.keyslots("nobody-here").await.unwrap());
    assert_ne!(decoy, anon.keyslots("someone-else").await.unwrap());
    assert_eq!(anon.challenge("nobody-here").await.unwrap().len(), 32);
    for r in [
        anon.get_blob(&Id::random(), 1 << 20).await.map(|_| ()),
        anon.get_node(&Id::random()).await.map(|_| ()),
    ] {
        assert!(matches!(r, Err(Error::Api { status: 401, .. })), "{r:?}");
    }
}
