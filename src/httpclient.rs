//! A very small HTTP/1.1 client for talking to a registry.
//!
//! Deliberately not a general-purpose client. It speaks to one origin, opens a
//! fresh connection per request, follows no redirects, and does no TLS. A
//! subscriber polls a handful of endpoints on an interval, so connection
//! pooling would buy nothing, and every feature not implemented here is a
//! feature that cannot go wrong in a security-relevant path.
//!
//! TLS is out of scope on purpose: `registryd` binds loopback and expects a
//! reverse proxy in front of it for anything reachable. Note that transport
//! security is not what makes the import safe in any case. Everything a
//! subscriber acts on is either a signed tree or a content-addressed body, both
//! of which are checked after they arrive (see [`crate::import`]), so a
//! tampering network gets rejected bytes rather than trusted ones.

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::header::{CONTENT_TYPE, HOST};
use hyper::{Method, Request, StatusCode};
use hyper_util::rt::TokioIo;
use tokio::net::TcpStream;

use crate::error::{RegistryError, Result};

/// A client bound to one registry origin.
#[derive(Debug, Clone)]
pub struct RegistryClient {
    base: String,
    authority: String,
}

/// An HTTP response: status plus the body as text.
#[derive(Debug, Clone)]
pub struct HttpResponse {
    /// HTTP status code.
    pub status: u16,
    /// Response body, as received.
    pub body: String,
}

impl HttpResponse {
    /// True for 2xx.
    pub fn is_success(&self) -> bool {
        (200..300).contains(&self.status)
    }

    /// The body if this was a 2xx, otherwise an error carrying the registry's
    /// own error code when it sent one.
    pub fn ok_body(self, what: &str) -> Result<String> {
        if self.is_success() {
            return Ok(self.body);
        }
        let detail = serde_json::from_str::<serde_json::Value>(&self.body)
            .ok()
            .and_then(|v| {
                let e = v.get("error")?;
                Some(format!(
                    "{} {}",
                    e.get("code").and_then(|c| c.as_str()).unwrap_or("?"),
                    e.get("message").and_then(|m| m.as_str()).unwrap_or("")
                ))
            })
            .unwrap_or_else(|| self.body.chars().take(200).collect());
        Err(RegistryError::Core(format!(
            "{what} failed with HTTP {}: {detail}",
            self.status
        )))
    }
}

impl RegistryClient {
    /// Build a client for a base URL such as `http://127.0.0.1:8088`.
    ///
    /// Only `http://` is accepted; an `https://` URL is refused loudly rather
    /// than silently downgraded, since a caller who wrote `https` is expecting
    /// something this does not provide.
    pub fn new(base_url: &str) -> Result<Self> {
        let base = base_url.trim_end_matches('/').to_string();
        let authority = base
            .strip_prefix("http://")
            .ok_or_else(|| {
                RegistryError::Core(format!(
                    "{base_url:?} is not an http:// URL (this client does not do TLS; \
                     terminate it in a reverse proxy and point here at the plaintext side)"
                ))
            })?
            .split('/')
            .next()
            .unwrap_or_default()
            .to_string();

        if authority.is_empty() {
            return Err(RegistryError::Core(format!("{base_url:?} has no host")));
        }
        Ok(Self { base, authority })
    }

    /// The base URL this client talks to.
    pub fn base_url(&self) -> &str {
        &self.base
    }

    /// Host and port, with a default port filled in when the URL omitted it.
    fn socket_addr(&self) -> String {
        if self.authority.contains(':') {
            self.authority.clone()
        } else {
            format!("{}:80", self.authority)
        }
    }

    async fn send(&self, method: Method, path: &str, body: Option<String>) -> Result<HttpResponse> {
        let stream = TcpStream::connect(self.socket_addr())
            .await
            .map_err(|e| RegistryError::Core(format!("cannot reach {}: {e}", self.base)))?;
        let io = TokioIo::new(stream);

        let (mut sender, conn) = hyper::client::conn::http1::handshake(io)
            .await
            .map_err(|e| RegistryError::Core(format!("HTTP handshake failed: {e}")))?;

        // The connection task drives the socket. It ends when the response is
        // complete, which is why a fresh connection per request is fine here.
        tokio::spawn(async move {
            let _ = conn.await;
        });

        let has_body = body.is_some();
        let mut builder = Request::builder()
            .method(method)
            .uri(path)
            .header(HOST, self.authority.clone());
        if has_body {
            builder = builder.header(CONTENT_TYPE, "application/json");
        }
        let request = builder
            .body(Full::new(Bytes::from(body.unwrap_or_default())))
            .map_err(|e| RegistryError::Core(format!("cannot build request: {e}")))?;

        let response = sender
            .send_request(request)
            .await
            .map_err(|e| RegistryError::Core(format!("request to {path} failed: {e}")))?;

        let status = response.status();
        let collected = response
            .into_body()
            .collect()
            .await
            .map_err(|e| RegistryError::Core(format!("reading response from {path}: {e}")))?;
        let text = String::from_utf8(collected.to_bytes().to_vec())
            .map_err(|e| RegistryError::Core(format!("response from {path} is not UTF-8: {e}")))?;

        Ok(HttpResponse {
            status: status.as_u16(),
            body: text,
        })
    }

    /// GET a path, returning the raw response.
    pub async fn get(&self, path: &str) -> Result<HttpResponse> {
        self.send(Method::GET, path, None).await
    }

    /// POST a JSON body, returning the raw response.
    pub async fn post(&self, path: &str, body: String) -> Result<HttpResponse> {
        self.send(Method::POST, path, Some(body)).await
    }

    /// GET a path and parse the body as `T`, erroring on any non-2xx.
    pub async fn get_json<T: serde::de::DeserializeOwned>(&self, path: &str) -> Result<T> {
        let text = self.get(path).await?.ok_body(path)?;
        serde_json::from_str(&text)
            .map_err(|e| RegistryError::Core(format!("{path} returned unparseable JSON: {e}")))
    }

    /// GET a path and return the body verbatim, erroring on any non-2xx.
    ///
    /// Used for signed trees and definition bodies, which must not be parsed
    /// and re-serialized on the way through: their bytes are what gets checked.
    pub async fn get_raw(&self, path: &str) -> Result<String> {
        self.get(path).await?.ok_body(path)
    }

    /// True when the registry answers `/health`.
    pub async fn healthy(&self) -> bool {
        matches!(self.get("/health").await, Ok(r) if r.status == StatusCode::OK.as_u16())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_https_rather_than_downgrading() {
        // A caller who wrote https is expecting TLS. Silently speaking
        // plaintext to port 443 would be worse than refusing.
        let err = RegistryClient::new("https://registry.example").unwrap_err();
        assert!(err.to_string().contains("does not do TLS"));
    }

    #[test]
    fn parses_authority_and_defaults_the_port() {
        let c = RegistryClient::new("http://127.0.0.1:8088/").unwrap();
        assert_eq!(c.base_url(), "http://127.0.0.1:8088");
        assert_eq!(c.socket_addr(), "127.0.0.1:8088");

        let c = RegistryClient::new("http://registry.example").unwrap();
        assert_eq!(c.socket_addr(), "registry.example:80");
    }

    #[test]
    fn rejects_a_url_with_no_host() {
        assert!(RegistryClient::new("http://").is_err());
        assert!(RegistryClient::new("not a url").is_err());
    }

    #[test]
    fn error_bodies_surface_the_registry_code() {
        // The subscriber reports why the registry said no, not just the status.
        let r = HttpResponse {
            status: 403,
            body: r#"{"error":{"code":"NOT_NAMESPACE_OWNER","message":"nope"}}"#.to_string(),
        };
        let err = r.ok_body("POST /templates").unwrap_err().to_string();
        assert!(err.contains("403"));
        assert!(err.contains("NOT_NAMESPACE_OWNER"));
    }

    #[test]
    fn success_bodies_pass_through_verbatim() {
        let r = HttpResponse {
            status: 200,
            body: "  {\"a\":1}  ".to_string(),
        };
        assert_eq!(r.ok_body("x").unwrap(), "  {\"a\":1}  ");
    }
}
