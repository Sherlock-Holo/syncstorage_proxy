#![feature(impl_trait_in_assoc_type)]

use std::convert::Infallible;
use std::error::Error;
use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::str::FromStr;
use std::task::{Context, Poll};

use axum::body::Body;
use axum::extract::Request;
use axum::http::{StatusCode, Uri};
use axum::response::Response;
use axum::Router;
use bytes::BytesMut;
use clap::Parser;
use futures_util::TryStreamExt;
use http_body_util::{BodyExt, Full};
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioExecutor;
use tower::Service;
use tracing::debug;
use tracing::level_filters::LevelFilter;
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
}

pub async fn run() -> anyhow::Result<()> {
    let args = Args::parse();

    init_log(args.debug);

    let router = Router::new().fallback_service(Handler {
        uri: Uri::from_str(&args.uri)?,
        client: Client::builder(TokioExecutor::new()).build_http(),
    });

    let listener = tokio::net::TcpListener::bind(args.listen_addr).await?;
    axum::serve(listener, router).await?;

    panic!("stopped")
}

#[derive(Debug, Clone)]
struct Handler {
    uri: Uri,
    client: Client<HttpConnector, Body>,
}

impl Service<Request> for Handler {
    type Response = Response;
    type Error = Infallible;
    type Future = impl Future<Output = Result<Self::Response, Self::Error>> + Send + 'static;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, req: Request) -> Self::Future {
        let client = self.client.clone();
        let uri = self.uri.clone();

        async move {
            let (mut parts, body) = req.into_parts();

            debug!(?parts, "get parts");

            let body = match body
                .into_data_stream()
                .try_fold(BytesMut::new(), |mut buf, data| async move {
                    buf.extend(data);

                    Ok::<_, axum::Error>(buf)
                })
                .await
            {
                Err(err) => {
                    return Ok(create_err_resp(err));
                }

                Ok(body) => body,
            };

            debug!(body = %String::from_utf8_lossy(&body), "get body");

            let mut uri_parts = uri.into_parts();
            uri_parts.path_and_query = parts.uri.path_and_query().cloned();

            match Uri::from_parts(uri_parts) {
                Err(err) => {
                    return Ok(create_err_resp(err));
                }

                Ok(uri) => {
                    parts.uri = uri;
                }
            }

            let request = Request::from_parts(parts, Body::new(Full::new(body.freeze())));
            match client.request(request).await {
                Err(err) => Ok(Response::new(Body::from(err.to_string()))),

                Ok(resp) => {
                    let (parts, body) = resp.into_parts();
                    let body = match body
                        .into_data_stream()
                        .try_fold(BytesMut::new(), |mut buf, data| async move {
                            buf.extend(data);

                            Ok::<_, hyper::Error>(buf)
                        })
                        .await
                    {
                        Err(err) => {
                            return Ok(create_err_resp(err));
                        }

                        Ok(body) => body,
                    };

                    debug!(body = %String::from_utf8_lossy(&body), "get response body");

                    Ok(Response::from_parts(
                        parts,
                        Body::new(Full::new(body.freeze())),
                    ))
                }
            }
        }
    }
}

fn create_err_resp<E: Error>(err: E) -> Response {
    let mut resp = Response::new(Body::from(err.to_string()));
    *resp.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;

    resp
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
