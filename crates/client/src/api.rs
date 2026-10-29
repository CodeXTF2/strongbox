//! Thin typed wrapper over the `/v1` HTTP API.

use reqwest::{Method, RequestBuilder, Response, StatusCode};
use serde::de::DeserializeOwned;
use serde::Serialize;
use strongbox_core::keyslot::Keyslot;
use strongbox_core::Id;
use strongbox_proto::*;
use zeroize::Zeroizing;

use crate::{Error, Result};

#[derive(Clone)]
pub struct Api {
    http: reqwest::Client,
    base: url::Url,
    /// Session token, wiped from memory when the `Api` is dropped.
    token: Option<Zeroizing<String>>,
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
            // Never follow redirects. The API has none, and reqwest keeps the Authorization
            // header on a same-host redirect even from https:// to http://, which would send
            // the session token (and, for 307/308, the body) in clear text past the
            // https-only check above.
            .redirect(reqwest::redirect::Policy::none())
            .https_only(base.scheme() == "https")
            .connect_timeout(std::time::Duration::from_secs(20))
            .read_timeout(std::time::Duration::from_secs(120))
            .build()?;
        Ok(Api {
            http,
            base,
            token: None,
        })
    }

    pub fn set_token(&mut self, token: String) {
        self.token = Some(Zeroizing::new(token));
    }

    fn req(&self, method: Method, path: &str) -> RequestBuilder {
        let url = self
            .base
            .join(path.trim_start_matches('/'))
            .expect("static API paths are valid");
        let rb = self.http.request(method, url);
        match &self.token {
            Some(t) => rb.bearer_auth(t.as_str()),
            None => rb,
        }
    }

    async fn check(resp: Response) -> Result<Response> {
        let status = resp.status();
        if status.is_success() {
            return Ok(resp);
        }
        let body = resp.text().await.unwrap_or_default();
        match serde_json::from_str::<ApiError>(&body) {
            Ok(e)
                if status == StatusCode::CONFLICT
                    && e.code == ErrorCode::Conflict
                    && !e.conflicts.is_empty() =>
            {
                Err(Error::Conflict(e.conflicts))
            }
            Ok(e) => Err(Error::Api {
                status: status.as_u16(),
                code: Some(e.code),
                message: e.message,
            }),
            Err(_) => Err(Error::Api {
                status: status.as_u16(),
                code: None,
                message: body,
            }),
        }
    }

    async fn json<T: DeserializeOwned>(&self, rb: RequestBuilder) -> Result<T> {
        Ok(Self::check(rb.send().await?).await?.json().await?)
    }

    async fn post<B: Serialize, T: DeserializeOwned>(&self, path: &str, body: &B) -> Result<T> {
        self.json(self.req(Method::POST, path).json(body)).await
    }

    pub async fn info(&self) -> Result<ServerInfo> {
        self.json(self.req(Method::GET, "/v1/info")).await
    }

    pub async fn register(&self, req: &RegisterRequest) -> Result<()> {
        Self::check(
            self.req(Method::POST, "/v1/accounts")
                .json(req)
                .send()
                .await?,
        )
        .await?;
        Ok(())
    }

    pub async fn keyslots(&self, username: &str) -> Result<Vec<Keyslot>> {
        // The username becomes a URL path segment: allow only what the server accepts.
        if !username
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"._-".contains(&b))
        {
            return Err(Error::Invalid(
                "username must be 3-64 chars of a-z 0-9 . _ -".into(),
            ));
        }
        let r: KeyslotsResponse = self
            .json(self.req(Method::GET, &format!("/v1/accounts/{username}/keyslots")))
            .await?;
        Ok(r.keyslots)
    }

    pub async fn challenge(&self, username: &str) -> Result<Vec<u8>> {
        let r: ChallengeResponse = self
            .post(
                "/v1/auth/challenge",
                &ChallengeRequest {
                    username: username.into(),
                },
            )
            .await?;
        Ok(r.challenge)
    }

    pub async fn session(&self, req: &SessionRequest) -> Result<SessionResponse> {
        self.post("/v1/auth/session", req).await
    }

    pub async fn logout(&self) -> Result<()> {
        Self::check(self.req(Method::DELETE, "/v1/auth/session").send().await?).await?;
        Ok(())
    }

    /// Permanently delete the signed-in account on the server.
    pub async fn delete_account(&self) -> Result<()> {
        Self::check(self.req(Method::DELETE, "/v1/accounts").send().await?).await?;
        Ok(())
    }

    pub async fn put_keyslot(&self, slot: &Keyslot) -> Result<()> {
        Self::check(
            self.req(Method::PUT, &format!("/v1/keyslots/{}", slot.id))
                .json(slot)
                .send()
                .await?,
        )
        .await?;
        Ok(())
    }

    pub async fn delete_keyslot(&self, id: &Id) -> Result<()> {
        Self::check(
            self.req(Method::DELETE, &format!("/v1/keyslots/{id}"))
                .send()
                .await?,
        )
        .await?;
        Ok(())
    }

    /// `Ok(None)` if the node does not exist (or was deleted).
    pub async fn get_node(&self, id: &Id) -> Result<Option<(u64, Vec<u8>)>> {
        let resp = self
            .req(Method::GET, &format!("/v1/nodes/{id}"))
            .send()
            .await?;
        if resp.status() == StatusCode::NOT_FOUND {
            return Ok(None);
        }
        let resp = Self::check(resp).await?;
        let version = resp
            .headers()
            .get(NODE_VERSION_HEADER)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse().ok())
            .ok_or_else(|| Error::Invalid("missing node version header".into()))?;
        Ok(Some((version, resp.bytes().await?.to_vec())))
    }

    pub async fn changes(&self, since: u64) -> Result<ChangesResponse> {
        self.json(self.req(Method::GET, &format!("/v1/changes?since={since}")))
            .await
    }

    pub async fn commit(&self, req: &CommitRequest) -> Result<CommitResponse> {
        self.post("/v1/commit", req).await
    }

    pub async fn put_blob(&self, id: &Id, data: Vec<u8>) -> Result<()> {
        Self::check(
            self.req(Method::PUT, &format!("/v1/blobs/{id}"))
                .body(data)
                .send()
                .await?,
        )
        .await?;
        Ok(())
    }

    /// Fetch a blob, refusing bodies over `max_len` (the server is not trusted to bound them).
    pub async fn get_blob(&self, id: &Id, max_len: usize) -> Result<Vec<u8>> {
        let mut resp = Self::check(
            self.req(Method::GET, &format!("/v1/blobs/{id}"))
                .send()
                .await?,
        )
        .await?;
        let too_big = || Error::Invalid(format!("server returned an oversized blob {id}"));
        if resp.content_length().is_some_and(|n| n > max_len as u64) {
            return Err(too_big());
        }
        let mut out = Vec::new();
        while let Some(part) = resp.chunk().await? {
            if out.len() + part.len() > max_len {
                return Err(too_big());
            }
            out.extend_from_slice(&part);
        }
        Ok(out)
    }

    pub async fn delete_blob(&self, id: &Id) -> Result<()> {
        Self::check(
            self.req(Method::DELETE, &format!("/v1/blobs/{id}"))
                .send()
                .await?,
        )
        .await?;
        Ok(())
    }

    pub async fn list_blobs(&self, after: Option<&Id>) -> Result<BlobListResponse> {
        let path = match after {
            Some(a) => format!("/v1/blobs?after={a}"),
            None => "/v1/blobs".to_string(),
        };
        self.json(self.req(Method::GET, &path)).await
    }

    pub async fn usage(&self) -> Result<UsageResponse> {
        self.json(self.req(Method::GET, "/v1/usage")).await
    }

    // ---------------- /v2 deniable vaults

    pub async fn create_vault(&self, req: &CreateVaultRequest) -> Result<VaultLayout> {
        self.post("/v2/vaults", req).await
    }

    pub async fn vault_record(&self, lookup: &[u8]) -> Result<Vec<u8>> {
        let r: RecordResponse = self
            .json(self.req(Method::GET, &format!("/v2/lookup/{}", hex::encode(lookup))))
            .await?;
        Ok(r.record)
    }

    pub async fn update_vault_record(&self, req: &UpdateRecordRequest) -> Result<()> {
        Self::check(self.req(Method::PUT, "/v2/record").json(req).send().await?).await?;
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
        Self::check(self.req(Method::DELETE, "/v2/auth/session").send().await?).await?;
        Ok(())
    }

    pub async fn vault_members(&self) -> Result<MembersResponse> {
        self.json(self.req(Method::GET, "/v2/members")).await
    }

    pub async fn add_vault_member(&self, req: &AddMemberRequest) -> Result<()> {
        Self::check(
            self.req(Method::POST, "/v2/members")
                .json(req)
                .send()
                .await?,
        )
        .await?;
        Ok(())
    }

    pub async fn remove_vault_member(&self, id: &str) -> Result<()> {
        Self::check(
            self.req(Method::DELETE, &format!("/v2/members/{id}"))
                .send()
                .await?,
        )
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
        let mut resp = Self::check(
            self.req(
                Method::GET,
                &format!("/v2/slots/{slot}/blocks?start={start}&count={count}"),
            )
            .send()
            .await?,
        )
        .await?;
        let want = count as usize * block_size;
        let mut out = Vec::with_capacity(want);
        while let Some(part) = resp.chunk().await? {
            if out.len() + part.len() > want {
                return Err(Error::Invalid(
                    "server returned too many block bytes".into(),
                ));
            }
            out.extend_from_slice(&part);
        }
        if out.len() != want {
            return Err(Error::Invalid("server returned a short block read".into()));
        }
        Ok(out)
    }

    pub async fn write_blocks(&self, slot: u32, start: u32, data: Vec<u8>) -> Result<()> {
        Self::check(
            self.req(
                Method::PUT,
                &format!("/v2/slots/{slot}/blocks?start={start}"),
            )
            .body(data)
            .send()
            .await?,
        )
        .await?;
        Ok(())
    }
}
