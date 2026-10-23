use std::error::Error as StdError;
use std::fmt;
use std::io;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use anyhow::Result;
use bytes::Bytes;
use const_format::formatcp;
use displaydoc::Display;
use futures::{
    future,
    stream::{self, StreamExt, TryStream, TryStreamExt},
};
use reqwest::{
    Body, Client as HttpClient, Response, StatusCode, Url,
    header::{AUTHORIZATION, HeaderMap, HeaderValue, USER_AGENT},
};
use serde::Deserialize;

use crate::config::ServerConfig;
use crate::version::ATTIC_DISTRIBUTOR;
use attic::api::v1::cache_config::{CacheConfig, CreateCacheRequest};
use attic::api::v1::get_missing_paths::{GetMissingPathsRequest, GetMissingPathsResponse};
use attic::api::v1::upload_path::{
    ATTIC_NAR_INFO, ATTIC_NAR_INFO_PREAMBLE_SIZE, FinalizeUploadSessionResponse,
    StartUploadPathSessionRequest, StartUploadPathSessionResponse, UploadPathNarInfo,
    UploadPathResult,
};
use attic::cache::CacheName;
use attic::nix_store::StorePathHash;

/// The User-Agent string of Attic.
const ATTIC_USER_AGENT: &str =
    formatcp!("Attic/{} ({})", env!("CARGO_PKG_NAME"), ATTIC_DISTRIBUTOR);

/// The size threshold to send the upload info as part of the PUT body.
const NAR_INFO_PREAMBLE_THRESHOLD: usize = 4 * 1024; // 4 KiB
const UPLOAD_PROGRESS_CHUNK_SIZE: usize = 128 * 1024;

/// The Attic API client.
#[derive(Debug, Clone)]
pub struct ApiClient {
    /// Base endpoint of the server.
    endpoint: Url,

    /// An initialized HTTP client.
    client: HttpClient,
}

/// An API error.
#[derive(Debug, Display)]
pub enum ApiError {
    /// {0}
    Structured(StructuredApiError),

    /// HTTP {0}: {1}
    Unstructured(StatusCode, String),
}

#[derive(Debug, Clone, Deserialize)]
pub struct StructuredApiError {
    #[allow(dead_code)]
    code: u16,
    error: String,
    message: String,
}

impl ApiClient {
    pub fn from_server_config(config: ServerConfig) -> Result<Self> {
        let client = build_http_client(config.token()?.as_deref());

        Ok(Self {
            endpoint: Url::parse(&config.endpoint)?,
            client,
        })
    }

    /// Sets the API endpoint of this client.
    pub fn set_endpoint(&mut self, endpoint: &str) -> Result<()> {
        self.endpoint = Url::parse(endpoint)?;
        Ok(())
    }

    /// Returns the configuration of a cache.
    pub async fn get_cache_config(&self, cache: &CacheName) -> Result<CacheConfig> {
        let endpoint = self
            .endpoint
            .join("_api/v1/cache-config/")?
            .join(cache.as_str())?;

        let res = self.client.get(endpoint).send().await?;

        if res.status().is_success() {
            let cache_config = res.json().await?;
            Ok(cache_config)
        } else {
            let api_error = ApiError::try_from_response(res).await?;
            Err(api_error.into())
        }
    }

    /// Creates a cache.
    pub async fn create_cache(&self, cache: &CacheName, request: CreateCacheRequest) -> Result<()> {
        let endpoint = self
            .endpoint
            .join("_api/v1/cache-config/")?
            .join(cache.as_str())?;

        let res = self.client.post(endpoint).json(&request).send().await?;

        if res.status().is_success() {
            Ok(())
        } else {
            let api_error = ApiError::try_from_response(res).await?;
            Err(api_error.into())
        }
    }

    /// Configures a cache.
    pub async fn configure_cache(&self, cache: &CacheName, config: &CacheConfig) -> Result<()> {
        let endpoint = self
            .endpoint
            .join("_api/v1/cache-config/")?
            .join(cache.as_str())?;

        let res = self.client.patch(endpoint).json(&config).send().await?;

        if res.status().is_success() {
            Ok(())
        } else {
            let api_error = ApiError::try_from_response(res).await?;
            Err(api_error.into())
        }
    }

    /// Destroys a cache.
    pub async fn destroy_cache(&self, cache: &CacheName) -> Result<()> {
        let endpoint = self
            .endpoint
            .join("_api/v1/cache-config/")?
            .join(cache.as_str())?;

        let res = self.client.delete(endpoint).send().await?;

        if res.status().is_success() {
            Ok(())
        } else {
            let api_error = ApiError::try_from_response(res).await?;
            Err(api_error.into())
        }
    }

    /// Returns paths missing from a cache.
    pub async fn get_missing_paths(
        &self,
        cache: &CacheName,
        store_path_hashes: Vec<StorePathHash>,
    ) -> Result<GetMissingPathsResponse> {
        let endpoint = self.endpoint.join("_api/v1/get-missing-paths")?;
        let payload = GetMissingPathsRequest {
            cache: cache.to_owned(),
            store_path_hashes,
        };

        let res = self.client.post(endpoint).json(&payload).send().await?;

        if res.status().is_success() {
            let cache_config = res.json().await?;
            Ok(cache_config)
        } else {
            let api_error = ApiError::try_from_response(res).await?;
            Err(api_error.into())
        }
    }

    /// Uploads a path.
    pub async fn upload_path<S>(
        &self,
        nar_info: UploadPathNarInfo,
        stream: S,
        force_preamble: bool,
    ) -> Result<Option<UploadPathResult>>
    where
        S: TryStream<Ok = Bytes> + Send + Sync + 'static,
        S::Error: Into<Box<dyn StdError + Send + Sync>> + Send + Sync,
    {
        let endpoint = self.endpoint.join("_api/v1/upload-path")?;
        let upload_info_json = serde_json::to_string(&nar_info)?;

        let mut req = self.client.put(endpoint);

        if force_preamble || upload_info_json.len() >= NAR_INFO_PREAMBLE_THRESHOLD {
            let preamble = Bytes::from(upload_info_json);
            let preamble_len = preamble.len();
            let preamble_stream = stream::once(future::ok(preamble));

            let chained = preamble_stream.chain(stream.into_stream());
            req = req
                .header(ATTIC_NAR_INFO_PREAMBLE_SIZE, preamble_len)
                .body(Body::wrap_stream(chained));
        } else {
            req = req
                .header(ATTIC_NAR_INFO, HeaderValue::from_str(&upload_info_json)?)
                .body(Body::wrap_stream(stream));
        }

        let res = req.send().await?;

        if res.status().is_success() {
            match res.json().await {
                Ok(r) => Ok(Some(r)),
                Err(_) => Ok(None),
            }
        } else {
            let api_error = ApiError::try_from_response(res).await?;
            Err(api_error.into())
        }
    }

    /// Starts a chunked transport upload session.
    pub async fn start_upload_session(
        &self,
        nar_info: UploadPathNarInfo,
        chunk_size: Option<usize>,
    ) -> Result<StartUploadPathSessionResponse> {
        let endpoint = self.endpoint.join("_api/v1/upload-path/sessions")?;
        let payload = StartUploadPathSessionRequest {
            nar_info,
            chunk_size,
        };

        let res = self.client.post(endpoint).json(&payload).send().await?;
        if res.status().is_success() {
            Ok(res.json().await?)
        } else {
            let api_error = ApiError::try_from_response(res).await?;
            Err(api_error.into())
        }
    }

    /// Uploads a chunked transport upload session part, retrying transient errors.
    /// Reports each logical body byte at most once, even when it is retransmitted.
    pub async fn upload_session_part_with_progress<F>(
        &self,
        session_id: uuid::Uuid,
        seq: u32,
        bytes: Bytes,
        on_progress: F,
    ) -> Result<()>
    where
        F: Fn(u64) + Send + Sync + 'static,
    {
        let endpoint = self.endpoint.join(&format!(
            "_api/v1/upload-path/sessions/{}/parts/{}",
            session_id, seq
        ))?;

        let body_len = bytes.len();
        let on_progress = Arc::new(on_progress);
        let reported = Arc::new(AtomicUsize::new(0));
        let mut delay = Duration::from_secs(1);
        let mut attempt = 1;
        loop {
            let on_progress = on_progress.clone();
            let reported = reported.clone();
            let bytes = bytes.clone();
            let body_stream = stream::iter((0..body_len).step_by(UPLOAD_PROGRESS_CHUNK_SIZE)).map(
                move |offset| {
                    let end = (offset + UPLOAD_PROGRESS_CHUNK_SIZE).min(body_len);
                    let previous = reported.fetch_max(end, Ordering::Relaxed);
                    if end > previous {
                        on_progress((end - previous) as u64);
                    }
                    Ok::<_, io::Error>(bytes.slice(offset..end))
                },
            );

            let result: Result<()> = async {
                let res = self
                    .client
                    .put(endpoint.clone())
                    .timeout(Duration::from_secs(120))
                    .header(reqwest::header::CONTENT_LENGTH, body_len)
                    .body(Body::wrap_stream(body_stream))
                    .send()
                    .await?;
                if res.status().is_success() {
                    Ok(())
                } else {
                    Err(ApiError::try_from_response(res).await?.into())
                }
            }
            .await;

            match result {
                Ok(()) => return Ok(()),
                Err(error) => {
                    let retryable = error
                        .downcast_ref::<ApiError>()
                        .is_some_and(ApiError::is_retryable)
                        || error.downcast_ref::<reqwest::Error>().is_some_and(|e| {
                            e.is_timeout() || e.is_connect() || e.is_request() || e.is_body()
                        });
                    if !retryable || attempt == 5 {
                        return Err(error);
                    }
                    tracing::warn!(%session_id, seq, attempt, %error, "Retrying upload part");
                    tokio::time::sleep(delay).await;
                    delay *= 2;
                    attempt += 1;
                }
            }
        }
    }

    /// Finalizes a chunked transport upload session.
    pub async fn finalize_upload_session(
        &self,
        session_id: uuid::Uuid,
    ) -> Result<FinalizeUploadSessionResponse> {
        let endpoint = self.endpoint.join(&format!(
            "_api/v1/upload-path/sessions/{}/finalize",
            session_id
        ))?;

        let res = self.client.post(endpoint).send().await?;
        if res.status().is_success() {
            Ok(res.json().await?)
        } else {
            let api_error = ApiError::try_from_response(res).await?;
            Err(api_error.into())
        }
    }

    /// Aborts a chunked transport upload session.
    pub async fn abort_upload_session(&self, session_id: uuid::Uuid) -> Result<()> {
        let endpoint = self
            .endpoint
            .join(&format!("_api/v1/upload-path/sessions/{}", session_id))?;

        let res = self.client.delete(endpoint).send().await?;
        if res.status().is_success() {
            Ok(())
        } else {
            let api_error = ApiError::try_from_response(res).await?;
            Err(api_error.into())
        }
    }
}

impl StdError for ApiError {}

impl ApiError {
    pub fn status_code(&self) -> Option<StatusCode> {
        match self {
            Self::Structured(error) => StatusCode::from_u16(error.code).ok(),
            Self::Unstructured(status, _) => Some(*status),
        }
    }

    pub fn is_retryable(&self) -> bool {
        self.status_code().is_some_and(|status| {
            status == StatusCode::REQUEST_TIMEOUT
                || status == StatusCode::TOO_MANY_REQUESTS
                || status.is_server_error()
        })
    }

    async fn try_from_response(response: Response) -> Result<Self> {
        let status = response.status();
        // A truncated error body must not hide the status used for retries.
        let text = match response.text().await {
            Ok(text) => text,
            Err(error) => return Ok(Self::Unstructured(status, error.to_string())),
        };
        match serde_json::from_str(&text) {
            Ok(s) => Ok(Self::Structured(s)),
            Err(_) => Ok(Self::Unstructured(status, text)),
        }
    }
}

impl fmt::Display for StructuredApiError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.error, self.message)
    }
}

fn build_http_client(token: Option<&str>) -> HttpClient {
    let mut headers = HeaderMap::new();

    headers.insert(USER_AGENT, HeaderValue::from_str(ATTIC_USER_AGENT).unwrap());

    if let Some(token) = token {
        let auth_header = HeaderValue::from_str(&format!("bearer {}", token)).unwrap();
        headers.insert(AUTHORIZATION, auth_header);
    }

    reqwest::Client::builder()
        .default_headers(headers)
        .build()
        .unwrap()
}

#[cfg(test)]
mod tests {
    use super::*;

    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    // None means the body was received but the connection lost its response.
    async fn upload_part_with_responses(
        responses: &[Option<u16>],
        truncate_error_body: bool,
    ) -> Result<()> {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = Url::parse(&format!("http://{}/", listener.local_addr().unwrap())).unwrap();
        let api = ApiClient {
            endpoint,
            client: build_http_client(None),
        };
        let session_id = uuid::Uuid::new_v4();
        let bytes = Bytes::from(
            (0..UPLOAD_PROGRESS_CHUNK_SIZE * 2 + 17)
                .map(|i| (i % 251) as u8)
                .collect::<Vec<_>>(),
        );
        let expected = bytes.clone();
        let responses = responses.to_vec();
        let server = tokio::spawn(async move {
            for response in responses {
                let (mut socket, _) = listener.accept().await.unwrap();
                let mut request = Vec::new();
                let header_end = loop {
                    assert_ne!(socket.read_buf(&mut request).await.unwrap(), 0);
                    if let Some(end) = request.windows(4).position(|w| w == b"\r\n\r\n") {
                        break end + 4;
                    }
                };
                let headers = std::str::from_utf8(&request[..header_end]).unwrap();
                assert!(headers.starts_with(&format!(
                    "PUT /_api/v1/upload-path/sessions/{session_id}/parts/7 HTTP/1.1\r\n"
                )));
                assert!(
                    headers
                        .to_ascii_lowercase()
                        .contains(&format!("content-length: {}\r\n", expected.len()))
                );
                while request.len() - header_end < expected.len() {
                    assert_ne!(socket.read_buf(&mut request).await.unwrap(), 0);
                }
                assert_eq!(&request[header_end..], expected.as_ref());
                if let Some(status) = response {
                    let length = if truncate_error_body && status >= 400 {
                        100
                    } else {
                        0
                    };
                    socket
                        .write_all(
                            format!(
                                "HTTP/1.1 {status} Test\r\nContent-Length: {length}\r\nConnection: close\r\n\r\n"
                            )
                            .as_bytes(),
                        )
                        .await
                        .unwrap();
                }
            }
        });
        let reported = Arc::new(AtomicUsize::new(0));
        let progress = reported.clone();
        let result = tokio::time::timeout(
            Duration::from_secs(25),
            api.upload_session_part_with_progress(session_id, 7, bytes.clone(), move |len| {
                let total = progress.fetch_add(len as usize, Ordering::Relaxed) + len as usize;
                assert!(total <= UPLOAD_PROGRESS_CHUNK_SIZE * 2 + 17);
            }),
        )
        .await
        .unwrap();
        tokio::time::timeout(Duration::from_secs(1), server)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(reported.load(Ordering::Relaxed), bytes.len());
        result
    }

    #[tokio::test]
    async fn upload_part_replays_lost_response_and_transient_errors_without_double_progress() {
        upload_part_with_responses(&[None, Some(408), Some(429), Some(500), Some(200)], false)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn upload_part_retries_truncated_transient_error_responses() {
        upload_part_with_responses(&[Some(408), Some(429), Some(503), Some(200)], true)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn upload_part_stops_after_five_transient_failures() {
        let error = upload_part_with_responses(&[Some(503); 5], false)
            .await
            .unwrap_err();
        assert_eq!(
            error.downcast_ref::<ApiError>().unwrap().status_code(),
            Some(StatusCode::SERVICE_UNAVAILABLE)
        );
    }

    #[tokio::test]
    async fn upload_part_does_not_retry_permanent_errors() {
        for truncate_error_body in [false, true] {
            for status in [400, 401, 403, 404, 409] {
                let error = upload_part_with_responses(&[Some(status)], truncate_error_body)
                    .await
                    .unwrap_err();
                assert_eq!(
                    error.downcast_ref::<ApiError>().unwrap().status_code(),
                    StatusCode::from_u16(status).ok()
                );
            }
        }
    }
}
