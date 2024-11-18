use std::collections::HashSet;
use std::io;
use std::net::SocketAddr;
use std::str::FromStr;
use std::time::SystemTime;

use axum::body::Body;
use axum::extract::{Request, State};
use axum::http::{HeaderMap, StatusCode, Uri};
use axum::response::Response;
use axum::Router;
use base64::engine::general_purpose::URL_SAFE;
use base64::Engine;
use bytes::BytesMut;
use clap::Parser;
use futures_util::{select, FutureExt, TryStreamExt};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use http_body_util::{BodyExt, Full};
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioExecutor;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use tokio::signal::unix;
use tokio::signal::unix::SignalKind;
use tracing::level_filters::LevelFilter;
use tracing::{debug, error, info, instrument};
use tracing_subscriber::filter::Targets;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::{fmt, Registry};

#[derive(Debug, Parser)]
struct Args {
    #[arg(short, long)]
    uri: String,

    #[arg(short, long)]
    listen_addr: SocketAddr,

    #[arg(short, long)]
    debug: bool,

    #[arg(short('s'), long("secrets"))]
    master_secrets: String,

    #[arg(long("fxa-uid"))]
    fxa_uids: Vec<String>,
}

pub async fn run() -> anyhow::Result<()> {
    let args = Args::parse();

    init_log(args.debug);

    let handler = Handler {
        uri: Uri::from_str(&args.uri)?,
        client: Client::builder(TokioExecutor::new()).build_http(),
        secrets: Secrets::new(&args.master_secrets).map_err(|err| anyhow::anyhow!("{err}"))?,
        allowed_user_ids: args.fxa_uids.into_iter().collect(),
    };

    let router = Router::new().fallback(handle).with_state(handler);
    let listener = tokio::net::TcpListener::bind(args.listen_addr).await?;

    axum::serve(listener, router)
        .with_graceful_shutdown(signal_stop())
        .await?;

    Ok(())
}

async fn handle(State(mut handler): State<Handler>, headers: HeaderMap, req: Request) -> Response {
    handler
        .handle(req, headers)
        .await
        .unwrap_or_else(create_err_resp)
}

#[derive(Debug, Clone)]
struct Handler {
    uri: Uri,
    client: Client<HttpConnector, Body>,
    secrets: Secrets,
    allowed_user_ids: HashSet<String>,
}

impl Handler {
    #[instrument(level = "debug", err)]
    async fn handle(&mut self, req: Request, headers: HeaderMap) -> anyhow::Result<Response> {
        let (mut parts, body) = req.into_parts();

        debug!(?parts, "get parts");

        if !self.is_whitelist_path(&parts.uri) {
            let auth = match self.get_auth_header(&headers) {
                Err(status_code) => {
                    let mut resp = Response::new(Body::empty());
                    *resp.status_mut() = status_code;

                    return Ok(resp);
                }

                Ok(auth) => auth,
            };

            if !self.is_token_server_request(auth) {
                match self.get_user_id(&parts.uri, auth) {
                    Err(status_code) => {
                        let mut resp = Response::new(Body::empty());
                        *resp.status_mut() = status_code;

                        return Ok(resp);
                    }

                    Ok(user_id) => {
                        if !self.allowed_user_ids.contains(&user_id.fxa_uid) {
                            let mut resp = Response::new(Body::empty());
                            *resp.status_mut() = StatusCode::FORBIDDEN;

                            return Ok(resp);
                        }

                        // our token server is started by sycnstorage-rs
                        if user_id.tokenserver_origin != TokenserverOrigin::Rust {
                            let mut resp = Response::new(Body::empty());
                            *resp.status_mut() = StatusCode::FORBIDDEN;

                            return Ok(resp);
                        }

                        debug!(?user_id, "authorized user");
                    }
                }
            } else {
                debug!(auth, "release bearer request for now")
            }
        }

        let body = body
            .into_data_stream()
            .try_fold(BytesMut::new(), |mut buf, data| async move {
                buf.extend(data);

                Ok::<_, axum::Error>(buf)
            })
            .await?;

        debug!(body = %String::from_utf8_lossy(&body), "get body");

        let mut uri_parts = self.uri.clone().into_parts();
        uri_parts.path_and_query = parts.uri.path_and_query().cloned();

        parts.uri = Uri::from_parts(uri_parts)?;
        let request = Request::from_parts(parts, Body::new(Full::new(body.freeze())));
        let resp = self.client.request(request).await?;

        let (parts, body) = resp.into_parts();
        let body = body
            .into_data_stream()
            .try_fold(BytesMut::new(), |mut buf, data| async move {
                buf.extend(data);

                Ok::<_, hyper::Error>(buf)
            })
            .await?;

        debug!(body = %String::from_utf8_lossy(&body), "get response body");

        Ok(Response::from_parts(
            parts,
            Body::new(Full::new(body.freeze())),
        ))
    }

    #[instrument(level = "debug", err, ret)]
    fn get_auth_header<'a>(&self, headers: &'a HeaderMap) -> Result<&'a str, StatusCode> {
        let auth = match headers.get("authorization") {
            None => {
                error!("miss auth header");

                return Err(StatusCode::UNAUTHORIZED);
            }
            Some(auth) => match auth.to_str() {
                Err(err) => {
                    error!(%err, "convert auth value to str failed");

                    return Err(StatusCode::UNAUTHORIZED);
                }

                Ok(auth) => auth,
            },
        };

        Ok(auth)
    }

    #[instrument(level = "debug", err, ret)]
    fn get_user_id(&mut self, uri: &Uri, auth: &str) -> Result<HawkIdentifier, StatusCode> {
        if auth.len() < 5 || &auth[0..5] != "Hawk " {
            error!(auth, "unknown auth value");

            return Err(StatusCode::UNAUTHORIZED);
        }

        debug!(auth, "get auth value done");

        let auth = match auth[5..].parse::<hawk::Header>() {
            Err(err) => {
                error!(%err, "parse hawk header failed");

                return Err(StatusCode::UNAUTHORIZED);
            }

            Ok(auth) => auth,
        };

        debug!(?auth, "get hawk auth done");

        let id = match &auth.id {
            None => {
                error!("miss auth id");

                return Err(StatusCode::UNAUTHORIZED);
            }

            Some(id) => id,
        };

        let expiry = if uri.path().ends_with("/info/collections") {
            0
        } else {
            SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap()
                .as_secs()
        };

        let payload = match HawkPayload::extract_and_validate(id, &self.secrets, expiry) {
            Err(err) => {
                error!(%err, "extracting hawk payload failed");

                return Err(StatusCode::UNAUTHORIZED);
            }

            Ok(payload) => payload,
        };

        let puid = match Self::uid_from_path(uri) {
            Err(err) => {
                error!(%err, "uid from path failed");

                return Err(StatusCode::UNAUTHORIZED);
            }

            Ok(puid) => puid,
        };

        if payload.user_id != puid {
            error!("⚠️ Hawk UID not in URI: {:?} {:?}", payload.user_id, uri);

            return Err(StatusCode::UNAUTHORIZED);
        }

        let user_id = HawkIdentifier {
            legacy_id: payload.user_id,
            fxa_uid: payload.fxa_uid,
            fxa_kid: payload.fxa_kid,
            hashed_fxa_uid: payload.hashed_fxa_uid,
            hashed_device_id: payload.hashed_device_id,
            tokenserver_origin: payload.tokenserver_origin,
        };

        Ok(user_id)
    }

    fn is_whitelist_path(&self, uri: &Uri) -> bool {
        uri.path() == "/__heartbeat__"
    }

    fn is_token_server_request(&self, auth: &str) -> bool {
        auth.split_once(' ')
            .map(|(auth_type, _)| auth_type.eq_ignore_ascii_case("bearer"))
            .unwrap_or(false)
    }

    fn uid_from_path(uri: &Uri) -> anyhow::Result<u64> {
        // TODO: replace with proper path parser.
        // path: "/1.5/{uid}"
        let elements: Vec<&str> = uri.path().split('/').collect();
        if let Some(v) = elements.get(2) {
            let clean = match Self::urldecode(v) {
                Err(e) => {
                    return Err(anyhow::anyhow!(
                        "⚠️ HawkIdentifier Error invalid UID {:?} {:?}",
                        v,
                        e
                    ))
                }
                Ok(v) => v,
            };

            u64::from_str(&clean)
                .map_err(|e| anyhow::anyhow!("⚠️ HawkIdentifier Error invalid UID {:?} {:?}", v, e))
        } else {
            Err(anyhow::anyhow!(
                "⚠️ HawkIdentifier Error missing UID {:?}",
                uri
            ))
        }
    }

    fn urldecode(s: &str) -> anyhow::Result<String> {
        let decoded = urlencoding::decode(s)
            .inspect_err(|err| {
                error!("Extract: unclean urldecode entry: {:?} {:?}", s, err);
            })?
            .into_owned();

        Ok(decoded)
    }
}

fn create_err_resp(err: anyhow::Error) -> Response {
    let mut resp = Response::new(Body::from(err.to_string()));
    *resp.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;

    resp
}

#[derive(Clone, Debug, Default, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub struct HawkIdentifier {
    /// For MySQL database backends as the primary key
    pub legacy_id: u64,
    /// For NoSQL database backends that require randomly distributed primary keys
    pub fxa_uid: String,
    pub fxa_kid: String,
    pub hashed_fxa_uid: String,
    pub hashed_device_id: String,
    pub tokenserver_origin: TokenserverOrigin,
}

/// A parsed and authenticated JSON payload
/// extracted from the signed `id` property
/// of a Hawk `Authorization` header.
#[derive(Debug, Deserialize, PartialEq, Serialize)]
pub struct HawkPayload {
    /// Expiry time for the payload, in seconds.
    pub expires: f64,

    /// Base URI for the storage node.
    pub node: String,

    /// Salt used during HKDF-expansion of the token secret.
    pub salt: String,

    /// User identifier.
    #[serde(rename = "uid")]
    pub user_id: u64,

    #[serde(default)]
    pub fxa_uid: String,

    #[serde(default)]
    pub fxa_kid: String,

    #[serde(default)]
    pub hashed_fxa_uid: String,

    #[serde(default)]
    pub hashed_device_id: String,

    /// The Tokenserver that created this token.
    #[serde(default)]
    pub tokenserver_origin: TokenserverOrigin,
}

impl HawkPayload {
    /// Decode the `id` property of a Hawk header
    /// and verify the payload part against the signature part.
    fn extract_and_validate(
        id: &str,
        secrets: &Secrets,
        expiry: u64,
    ) -> anyhow::Result<HawkPayload> {
        let decoded_id = URL_SAFE.decode(id)?;
        if decoded_id.len() <= 32 {
            return Err(anyhow::anyhow!("not enough length"));
        }

        let payload_length = decoded_id.len() - 32;
        let payload = &decoded_id[0..payload_length];
        let signature = &decoded_id[payload_length..];

        Self::verify_hmac(payload, &secrets.signing_secret, signature)?;

        let payload: HawkPayload = serde_json::from_slice(payload)?;

        if expiry == 0 || (payload.expires.round() as u64) > expiry {
            Ok(payload)
        } else {
            Err(anyhow::anyhow!("expired"))
        }
    }

    /// Helper function for [HMAC](https://tools.ietf.org/html/rfc2104) verification.
    fn verify_hmac(info: &[u8], key: &[u8], expected: &[u8]) -> anyhow::Result<()> {
        let mut hmac = Hmac::<Sha256>::new_from_slice(key)?;
        hmac.update(info);
        hmac.verify(expected.into()).map_err(From::from)
    }
}

/// Secrets used during Hawk authentication.
#[derive(Clone, Debug)]
pub struct Secrets {
    /// The master secret in byte array form.
    ///
    /// The signing secret and token secret are derived from this.
    pub master_secret: Vec<u8>,

    /// The signing secret used during Hawk authentication.
    pub signing_secret: [u8; 32],
}

impl Secrets {
    /// Decode the master secret to a byte array
    /// and derive the signing secret from it.
    pub fn new(master_secret: &str) -> Result<Self, String> {
        let master_secret = master_secret.as_bytes().to_vec();
        let signing_secret = Self::hkdf_expand_32(
            b"services.mozilla.com/tokenlib/v1/signing",
            None,
            &master_secret,
        )?;

        Ok(Self {
            master_secret,
            signing_secret,
        })
    }

    /// Helper function for [HKDF](https://tools.ietf.org/html/rfc5869) expansion to 32 bytes.
    pub fn hkdf_expand_32(
        info: &[u8],
        salt: Option<&[u8]>,
        key: &[u8],
    ) -> Result<[u8; 32], String> {
        let mut result = [0u8; 32];
        let hkdf = Hkdf::<Sha256>::new(salt, key);
        hkdf.expand(info, &mut result)
            .map_err(|e| format!("HKDF Error: {:?}", e))?;

        Ok(result)
    }
}

#[derive(Clone, Copy, Default, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum TokenserverOrigin {
    /// The Python Tokenserver.
    #[default]
    Python,
    /// The Rust Tokenserver.
    Rust,
}

fn init_log(debug: bool) {
    let layer = fmt::layer()
        .pretty()
        .with_target(true)
        .with_writer(io::stderr);

    let level = if debug {
        LevelFilter::DEBUG
    } else {
        LevelFilter::INFO
    };

    let targets = Targets::new()
        .with_default(LevelFilter::DEBUG)
        .with_target("hyper_util", LevelFilter::OFF);

    Registry::default()
        .with(targets)
        .with(layer)
        .with(level)
        .init()
}

async fn signal_stop() {
    let mut term = unix::signal(SignalKind::terminate()).unwrap();
    let mut interrupt = unix::signal(SignalKind::interrupt()).unwrap();

    select! {
        _ = term.recv().fuse() => {}
        _ = interrupt.recv().fuse() => {}
    }

    info!("graceful stop")
}
