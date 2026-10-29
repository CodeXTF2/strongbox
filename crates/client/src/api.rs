//! Thin typed wrapper over the `/v1/info` and `/v2` HTTP API.

use reqwest::{Method, RequestBuilder, Response};
use serde::de::DeserializeOwned;
use serde::Serialize;
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

    /// Permanently delete the signed-in account on the server.
    pub async fn delete_account(&self) -> Result<()> {
        Self::check(self.req(Method::DELETE, "/v2/vaults").send().await?).await?;
        Ok(())
    }

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
