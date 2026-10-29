//! Thin typed wrapper over the `/v1/info` and `/v2` HTTP API.
//!
//! Only `info`, the username record lookup, sign-up and the channel hello travel in the clear.
//! Every other call is sealed (see `strongbox_core::channel`) once [`Api::open_channel`] has
//! succeeded, so a hostile proxy or a forged TLS certificate can neither read nor alter it.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use rand::RngCore;
use reqwest::Response;
use serde::de::DeserializeOwned;
use serde::Serialize;
use strongbox_core::channel::{self as ch, Method, RequestHead};
use strongbox_core::vault::{ENTRIES_LEN, HEADER_BLOCKS, HEADER_LEN};
use strongbox_core::Key;
use strongbox_proto::*;
use zeroize::Zeroizing;

use crate::{Error, Result};

/// One sealed-channel session.
struct Channel {
    sid: [u8; ch::SID_LEN],
    c2s: Key,
    s2c: Key,
    counter: AtomicU64,
}

#[derive(Clone)]
pub struct Api {
    http: reqwest::Client,
    base: url::Url,
    /// Session token, wiped from memory when the `Api` is dropped. Only ever sent inside the
    /// sealed channel.
    token: Option<Zeroizing<String>>,
    channel: Option<Arc<Channel>>,
}

/// Plain HTTP is only allowed to loopback (development); everything else must use HTTPS.
pub fn check_server_url(server: &str) -> Result<url::Url> {
    let url =
        url::Url::parse(server).map_err(|e| Error::Invalid(format!("bad server URL: {e}")))?;
    let loopback = matches!(url.host_str(), Some("localhost" | "127.0.0.1" | "[::1]"));
    match url.scheme() {
        "https" => Ok(url),
        "http" if loopback => Ok(url),
        _ => Err(Error::Invalid(
            "server URL must use https:// (http:// only for localhost)".into(),
        )),
    }
}

impl Api {
    pub fn new(server: &str) -> Result<Self> {
        let mut base = check_server_url(server)?;
        // `Url::join` replaces the last path segment unless the base ends in '/', which would
        // drop a path prefix like https://host/strongbox.
        if !base.path().ends_with('/') {
            base.set_path(&format!("{}/", base.path()));
        }
        let http = reqwest::Client::builder()
            .user_agent(concat!("strongbox/", env!("CARGO_PKG_VERSION")))
            // Never follow redirects. The API has none, and a redirect could point the clear
            // calls (and, for 307/308, their bodies) somewhere else.
            .redirect(reqwest::redirect::Policy::none())
            .https_only(base.scheme() == "https")
            .connect_timeout(std::time::Duration::from_secs(20))
            .read_timeout(std::time::Duration::from_secs(120))
            .build()?;
        Ok(Api {
            http,
            base,
            token: None,
            channel: None,
        })
    }

    pub fn set_token(&mut self, token: String) {
        self.token = Some(Zeroizing::new(token));
    }

    fn url(&self, path: &str) -> url::Url {
        self.base
            .join(path.trim_start_matches('/'))
            .expect("static API paths are valid")
    }

    async fn check(resp: Response) -> Result<Response> {
        let status = resp.status();
        if status.is_success() {
            return Ok(resp);
        }
        let body = resp.bytes().await.unwrap_or_default();
        Err(api_error(status.as_u16(), &body))
    }

    // ---------------- clear-text calls

    async fn plain_json<T: DeserializeOwned>(&self, rb: reqwest::RequestBuilder) -> Result<T> {
        Ok(Self::check(rb.send().await?).await?.json().await?)
    }

    pub async fn info(&self) -> Result<ServerInfo> {
        self.plain_json(self.http.get(self.url("/v1/info"))).await
    }

    /// Sign-up. Not sealed (no channel exists yet): it carries the member's transport key, so
    /// it must happen on a network the user trusts.
    pub async fn create_vault(&self, req: &CreateVaultRequest) -> Result<VaultLayout> {
        self.plain_json(self.http.post(self.url("/v2/vaults")).json(req))
            .await
    }

    pub async fn vault_record(&self, lookup: &[u8]) -> Result<Vec<u8>> {
        let r: RecordResponse = self
            .plain_json(
                self.http
                    .get(self.url(&format!("/v2/lookup/{}", hex::encode(lookup)))),
            )
            .await?;
        Ok(r.record)
    }

    // ---------------- the sealed channel

    /// Open a sealed channel as the member with this locator hash. Fails unless the server
    /// proves it holds the member's transport key, which a proxy cannot.
    pub async fn open_channel(&mut self, member_id: &[u8; 32], transport: &Key) -> Result<()> {
        let mut client_nonce = [0u8; ch::HELLO_NONCE_LEN];
        rand::thread_rng().fill_bytes(&mut client_nonce);
        let mut hello = member_id.to_vec();
        hello.extend_from_slice(&client_nonce);
        let resp = Self::check(
            self.http
                .post(self.url(CHANNEL_HELLO_PATH))
                .body(hello)
                .send()
                .await?,
        )
        .await?;
        let reply = resp.bytes().await?;
        if reply.len() != ch::HELLO_NONCE_LEN + ch::SID_LEN + 32 {
            return Err(Error::Invalid("malformed channel reply".into()));
        }
        let (server_nonce, rest) = reply.split_at(ch::HELLO_NONCE_LEN);
        let (sid, confirm) = rest.split_at(ch::SID_LEN);
        let want = ch::confirm_tag(transport, &client_nonce, server_nonce, sid);
        if !ch::ct_eq(&want, confirm) {
            return Err(Error::Invalid(
                "the server could not prove it is the server this account was created on".into(),
            ));
        }
        let (c2s, s2c) = ch::session_keys(transport, &client_nonce, server_nonce, sid);
        self.channel = Some(Arc::new(Channel {
            sid: sid.try_into().expect("split at SID_LEN"),
            c2s,
            s2c,
            counter: AtomicU64::new(0),
        }));
        Ok(())
    }

    /// One sealed round trip. Returns the inner status and body.
    async fn call(
        &self,
        method: Method,
        path: &str,
        json: bool,
        body: Vec<u8>,
    ) -> Result<(u16, Vec<u8>)> {
        let chan = self
            .channel
            .as_ref()
            .ok_or_else(|| Error::Invalid("secure channel is not open".into()))?;
        let counter = chan.counter.fetch_add(1, Ordering::SeqCst) + 1;
        let head = RequestHead {
            method,
            json,
            path: path.to_string(),
            token: self
                .token
                .as_ref()
                .map(|t| t.to_string())
                .unwrap_or_default(),
        };
        // Frame and seal in one buffer: block writes are megabytes.
        let mut msg = Vec::with_capacity(
            ch::REQUEST_HEADER_LEN + 5 + path.len() + head.token.len() + body.len() + 16,
        );
        msg.extend_from_slice(&chan.sid);
        msg.extend_from_slice(&counter.to_be_bytes());
        ch::encode_request_head(&head, &mut msg);
        msg.extend_from_slice(&body);
        drop(body);
        ch::seal_message_in_place(
            &chan.c2s,
            &chan.sid,
            counter,
            &mut msg,
            ch::REQUEST_HEADER_LEN,
        );
        let resp = Self::check(
            self.http
                .post(self.url(CHANNEL_RPC_PATH))
                .body(msg)
                .send()
                .await?,
        )
        .await?;
        let mut out = Vec::from(resp.bytes().await?);
        ch::open_message_in_place(&chan.s2c, &chan.sid, counter, &mut out, 0)
            .map_err(|_| Error::Invalid("the server's reply failed authentication".into()))?;
        if out.len() < 2 {
            return Err(Error::Invalid("malformed channel response".into()));
        }
        let status = u16::from_be_bytes([out[0], out[1]]);
        out.drain(..2);
        Ok((status, out))
    }

    async fn sealed_body(
        &self,
        method: Method,
        path: &str,
        json: bool,
        body: Vec<u8>,
    ) -> Result<Vec<u8>> {
        let (status, out) = self.call(method, path, json, body).await?;
        if (200..300).contains(&status) {
            Ok(out)
        } else {
            Err(api_error(status, &out))
        }
    }

    /// A sealed call with an optional JSON body.
    async fn sealed(&self, method: Method, path: &str, json: Option<Vec<u8>>) -> Result<Vec<u8>> {
        match json {
            Some(body) => self.sealed_body(method, path, true, body).await,
            None => self.sealed_body(method, path, false, Vec::new()).await,
        }
    }

    async fn sealed_json<T: DeserializeOwned>(
        &self,
        method: Method,
        path: &str,
        body: Option<Vec<u8>>,
    ) -> Result<T> {
        let out = self.sealed(method, path, body).await?;
        serde_json::from_slice(&out)
            .map_err(|_| Error::Invalid("the server sent a malformed reply".into()))
    }

    async fn post<B: Serialize, T: DeserializeOwned>(&self, path: &str, body: &B) -> Result<T> {
        self.sealed_json(Method::Post, path, Some(to_json(body)?))
            .await
    }

    /// `info`, but inside the sealed channel, so a proxy cannot have altered it.
    pub async fn sealed_info(&self) -> Result<ServerInfo> {
        self.sealed_json(Method::Get, "/v2/info", None).await
    }

    /// Permanently delete the signed-in account on the server.
    pub async fn delete_account(&self) -> Result<()> {
        self.sealed(Method::Delete, "/v2/vaults", None).await?;
        Ok(())
    }

    pub async fn update_vault_record(&self, req: &UpdateRecordRequest) -> Result<()> {
        self.sealed(Method::Put, "/v2/record", Some(to_json(req)?))
            .await?;
        Ok(())
    }

    pub async fn vault_challenge(&self, locator: &[u8]) -> Result<Vec<u8>> {
        let r: ChallengeResponse = self
            .post(
                "/v2/auth/challenge",
                &VaultChallengeRequest {
                    locator: locator.to_vec(),
                },
            )
            .await?;
        Ok(r.challenge)
    }

    pub async fn vault_session(&self, req: &VaultSessionRequest) -> Result<SessionResponse> {
        self.post("/v2/auth/session", req).await
    }

    pub async fn vault_logout(&self) -> Result<()> {
        self.sealed(Method::Delete, "/v2/auth/session", None)
            .await?;
        Ok(())
    }

    pub async fn vault_members(&self) -> Result<MembersResponse> {
        self.sealed_json(Method::Get, "/v2/members", None).await
    }

    pub async fn add_vault_member(&self, req: &AddMemberRequest) -> Result<()> {
        self.sealed(Method::Post, "/v2/members", Some(to_json(req)?))
            .await?;
        Ok(())
    }

    pub async fn remove_vault_member(&self, id: &str) -> Result<()> {
        self.sealed(Method::Delete, &format!("/v2/members/{id}"), None)
            .await?;
        Ok(())
    }

    /// Read `count` whole blocks; the response must be exactly that size.
    pub async fn read_blocks(
        &self,
        slot: u32,
        start: u32,
        count: u32,
        block_size: usize,
    ) -> Result<Vec<u8>> {
        let out = self
            .sealed(
                Method::Get,
                &format!("/v2/slots/{slot}/blocks?start={start}&count={count}"),
                None,
            )
            .await?;
        if out.len() != count as usize * block_size {
            return Err(Error::Invalid("server returned a short block read".into()));
        }
        Ok(out)
    }

    /// The entry tables of every slot (`ENTRIES_LEN` bytes per header copy, slots in order).
    pub async fn read_all_entries(&self, slots: u32) -> Result<Vec<u8>> {
        let out = self.sealed(Method::Get, "/v2/entries", None).await?;
        if out.len() != slots as usize * HEADER_BLOCKS as usize * ENTRIES_LEN {
            return Err(Error::Invalid("server returned a short entry read".into()));
        }
        Ok(out)
    }

    /// Both header copies of a slot, `HEADER_LEN` bytes each.
    pub async fn read_headers(&self, slot: u32) -> Result<Vec<u8>> {
        let out = self
            .sealed(Method::Get, &format!("/v2/slots/{slot}/headers"), None)
            .await?;
        if out.len() != HEADER_BLOCKS as usize * HEADER_LEN {
            return Err(Error::Invalid("server returned a short header read".into()));
        }
        Ok(out)
    }

    pub async fn write_header(&self, slot: u32, copy: u8, header: Vec<u8>) -> Result<()> {
        self.sealed_body(
            Method::Put,
            &format!("/v2/slots/{slot}/headers/{copy}"),
            false,
            header,
        )
        .await?;
        Ok(())
    }

    pub async fn write_blocks(&self, slot: u32, start: u32, data: Vec<u8>) -> Result<()> {
        self.sealed_body(
            Method::Put,
            &format!("/v2/slots/{slot}/blocks?start={start}"),
            false,
            data,
        )
        .await?;
        Ok(())
    }
}

fn to_json<B: Serialize>(body: &B) -> Result<Vec<u8>> {
    serde_json::to_vec(body).map_err(|e| Error::Invalid(format!("encoding request: {e}")))
}

fn api_error(status: u16, body: &[u8]) -> Error {
    match serde_json::from_slice::<ApiError>(body) {
        Ok(e) => Error::Api {
            status,
            code: Some(e.code),
            message: e.message,
        },
        Err(_) => Error::Api {
            status,
            code: None,
            message: String::from_utf8_lossy(body).into_owned(),
        },
    }
}
