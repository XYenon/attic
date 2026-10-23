//! Nix Binary Cache server.
//!
//! This module implements the Nix Binary Cache API.
//!
//! The implementation is based on the specifications at <https://github.com/fzakaria/nix-http-binary-cache-api-spec>.

use std::collections::VecDeque;
use std::io::Error as IoError;
use std::ops::Range;
use std::path::PathBuf;
use std::sync::Arc;

use anyhow::anyhow;
use axum::{
    Router,
    body::Body,
    extract::{Extension, Path},
    http::{HeaderMap, Method, StatusCode, header},
    response::{IntoResponse, Redirect, Response},
    routing::get,
};
use futures::TryStreamExt as _;
use futures::stream::BoxStream;
use http_range::{HttpRange, HttpRangeParseError};
use serde::Serialize;
use sha2::{Digest, Sha256};
use tokio_util::io::ReaderStream;
use tracing::instrument;

use crate::database::AtticDatabase;
use crate::database::entity::chunk::ChunkModel;
use crate::error::{ErrorKind, ServerError, ServerResult};
use crate::narinfo::NarInfo;
use crate::nix_manifest;
use crate::storage::{Download, StorageBackend, StorageBackendImpl};
use crate::{RequestState, State};
use attic::cache::CacheName;
use attic::io::merge_chunks;
use attic::mime;
use attic::nix_store::StorePathHash;

#[cfg(test)]
mod tests;

/// Returns the size of the compressed representation, checking chunk completeness.
fn nar_file_size(chunks: &[Option<ChunkModel>]) -> ServerResult<u64> {
    chunks.iter().try_fold(0_u64, |size, chunk| {
        let chunk = chunk.as_ref().ok_or(ErrorKind::IncompleteNar)?;
        let chunk_size = chunk
            .file_size
            .and_then(|size| u64::try_from(size).ok())
            .ok_or_else(|| ErrorKind::DatabaseError(anyhow!("Invalid chunk file size")))?;
        size.checked_add(chunk_size)
            .ok_or_else(|| ErrorKind::DatabaseError(anyhow!("NAR file size overflow")).into())
    })
}

/// Compares an If-None-Match list using weak comparison. Commas inside an
/// opaque tag are part of that tag, not list separators.
fn if_none_match(mut value: &str, etag: &str) -> bool {
    value = value.trim();
    if value == "*" {
        return true;
    }
    let etag = etag.strip_prefix("W/").unwrap_or(etag);
    let etag = etag
        .strip_prefix('"')
        .and_then(|etag| etag.strip_suffix('"'));
    while !value.is_empty() {
        value = value.trim_start_matches([',', ' ', '\t']);
        value = value.strip_prefix("W/").unwrap_or(value);
        let Some((tag, rest)) = value
            .strip_prefix('"')
            .and_then(|value| value.split_once('"'))
        else {
            return false;
        };
        value = rest.trim_start_matches([' ', '\t']);
        if !value.is_empty() && !value.starts_with(',') {
            return false;
        }
        if Some(tag) == etag {
            return true;
        }
    }
    false
}

/// Nix cache information.
///
/// An example of a correct response is as follows:
///
/// ```text
/// StoreDir: /nix/store
/// WantMassQuery: 1
/// Priority: 40
/// ```
#[derive(Debug, Clone, Serialize)]
struct NixCacheInfo {
    /// Whether this binary cache supports bulk queries.
    #[serde(rename = "WantMassQuery")]
    want_mass_query: bool,

    /// The Nix store path this binary cache uses.
    #[serde(rename = "StoreDir")]
    store_dir: PathBuf,

    /// The priority of the binary cache.
    ///
    /// A lower number denotes a higher priority.
    /// <https://cache.nixos.org> has a priority of 40.
    #[serde(rename = "Priority")]
    priority: i32,
}

impl IntoResponse for NixCacheInfo {
    fn into_response(self) -> Response {
        match nix_manifest::to_string(&self) {
            Ok(body) => Response::builder()
                .status(StatusCode::OK)
                .header("Content-Type", mime::NIX_CACHE_INFO)
                .body(body)
                .unwrap()
                .into_response(),
            Err(e) => e.into_response(),
        }
    }
}

/// Gets information on a cache.
#[instrument(skip_all, fields(cache_name))]
async fn get_nix_cache_info(
    Extension(state): Extension<State>,
    Extension(req_state): Extension<RequestState>,
    Path(cache_name): Path<CacheName>,
) -> ServerResult<NixCacheInfo> {
    let database = state.database().await?;
    let cache = req_state
        .auth
        .auth_cache(database, &cache_name, |cache, permission| {
            permission.require_pull()?;
            Ok(cache)
        })
        .await?;

    req_state.set_public_cache(cache.is_public);

    let info = NixCacheInfo {
        want_mass_query: true,
        store_dir: cache.store_dir.into(),
        priority: cache.priority,
    };

    Ok(info)
}

/// Gets various information on a store path hash.
///
/// `/:cache/:path`, which may be one of
/// - GET `/:cache/{storePathHash}.narinfo`
/// - HEAD `/:cache/{storePathHash}.narinfo`
/// - GET `/:cache/{storePathHash}.ls` (not implemented)
#[instrument(skip_all, fields(cache_name, path))]
#[axum_macros::debug_handler]
async fn get_store_path_info(
    Extension(state): Extension<State>,
    Extension(req_state): Extension<RequestState>,
    Path((cache_name, path)): Path<(CacheName, String)>,
) -> ServerResult<NarInfo> {
    let components: Vec<&str> = path.splitn(2, '.').collect();

    if components.len() != 2 {
        return Err(ErrorKind::NotFound.into());
    }

    // TODO: Other endpoints
    if components[1] != "narinfo" {
        return Err(ErrorKind::NotFound.into());
    }

    let store_path_hash = StorePathHash::new(components[0].to_string())?;

    tracing::debug!(
        "Received request for {}.narinfo in {:?}",
        store_path_hash.as_str(),
        cache_name
    );

    let (object, cache, nar, chunks) = state
        .database()
        .await?
        .find_object_and_chunks_by_store_path_hash(&cache_name, &store_path_hash, true)
        .await?;

    let permission = req_state
        .auth
        .get_permission_for_cache(&cache_name, cache.is_public);
    permission.require_pull()?;

    req_state.set_public_cache(cache.is_public);

    let file_size = nar_file_size(&chunks)?
        .try_into()
        .map_err(ServerError::database_error)?;
    let mut narinfo = object.to_nar_info(&nar, file_size)?;

    if narinfo.signature().is_none() {
        let keypair = cache.keypair()?;
        narinfo.sign(&keypair);
    }

    Ok(narinfo)
}

/// Gets a NAR.
///
/// - GET `:cache/nar/{storePathHash}.nar`
///
/// Here we use the store path hash not the NAR hash or file hash
/// for better logging. In reality, the files are deduplicated by
/// content-addressing.
#[instrument(skip_all, fields(cache_name, path))]
async fn get_nar(
    Extension(state): Extension<State>,
    Extension(req_state): Extension<RequestState>,
    Path((cache_name, path)): Path<(CacheName, String)>,
    method: Method,
    headers: HeaderMap,
) -> ServerResult<Response> {
    let components: Vec<&str> = path.splitn(2, '.').collect();

    if components.len() != 2 {
        return Err(ErrorKind::NotFound.into());
    }

    if components[1] != "nar" {
        return Err(ErrorKind::NotFound.into());
    }

    let store_path_hash = StorePathHash::new(components[0].to_string())?;

    tracing::debug!(
        "Received request for {}.nar in {:?}",
        store_path_hash.as_str(),
        cache_name
    );

    let database = state.database().await?;

    let (object, cache, _nar, chunks) = database
        .find_object_and_chunks_by_store_path_hash(&cache_name, &store_path_hash, true)
        .await?;

    let permission = req_state
        .auth
        .get_permission_for_cache(&cache_name, cache.is_public);
    permission.require_pull()?;

    req_state.set_public_cache(cache.is_public);

    let file_size = nar_file_size(&chunks)?;
    let mut hasher = Sha256::new();
    for chunk in chunks.iter().flatten() {
        let file_hash = chunk
            .file_hash
            .as_ref()
            .ok_or_else(|| ErrorKind::DatabaseError(anyhow!("Missing chunk file hash")))?;
        hasher.update(file_hash.as_bytes());
        hasher.update([0]);
    }
    // Bind the validator to compressed bytes, since recompression can change them
    // without changing the uncompressed NAR hash.
    let mut etag = format!("\"{}\"", hex::encode(hasher.finalize()));
    if chunks.len() == 1
        && let Some(storage_etag) = state
            .storage()
            .await?
            .file_etag(&chunks[0].as_ref().unwrap().remote_file.0)
            .await?
    {
        // A redirected GET exposes the storage service's validator, so HEAD
        // and conditional requests must use that same validator.
        etag = storage_etag;
    }

    let mut response = Response::builder()
        .header(header::CONTENT_TYPE, mime::NAR)
        .header(header::ACCEPT_RANGES, "bytes")
        .header(header::ETAG, &etag);

    // Preconditions are evaluated before Range and before opening any body.
    if headers.get_all(header::IF_NONE_MATCH).iter().any(|value| {
        value
            .to_str()
            .is_ok_and(|value| if_none_match(value, &etag))
    }) {
        if method == Method::GET {
            database.bump_object_last_accessed(object.id).await?;
        }
        return Ok(response
            .status(StatusCode::NOT_MODIFIED)
            .header(header::CONTENT_LENGTH, file_size)
            .body(Body::empty())
            .unwrap());
    }

    // Range applies only to GET. Ignore multipart ranges and invalid syntax;
    // a client can always fall back to downloading the full representation.
    let range = if method == Method::GET
        && headers.get_all(header::RANGE).iter().count() == 1
        && headers
            .get(header::IF_RANGE)
            .is_none_or(|value| value == etag.as_str())
        && let Some(value) = headers
            .get(header::RANGE)
            .and_then(|value| value.to_str().ok())
        && !value.contains(',')
    {
        match HttpRange::parse(value, file_size) {
            Ok(ranges) if file_size > 0 => ranges
                .first()
                .map(|range| range.start..range.start + range.length),
            Ok(_) | Err(HttpRangeParseError::NoOverlap) => {
                return Ok(response
                    .status(StatusCode::RANGE_NOT_SATISFIABLE)
                    .header(header::CONTENT_RANGE, format!("bytes */{file_size}"))
                    .body(Body::empty())
                    .unwrap());
            }
            Err(HttpRangeParseError::InvalidRange) => None,
        }
    } else {
        None
    };

    let selected = range.clone().unwrap_or(0..file_size);
    response = response.header(header::CONTENT_LENGTH, selected.end - selected.start);
    if range.is_some() {
        response = response.status(StatusCode::PARTIAL_CONTENT).header(
            header::CONTENT_RANGE,
            format!("bytes {}-{}/{file_size}", selected.start, selected.end - 1,),
        );
    }

    if method == Method::HEAD {
        return Ok(response.body(Body::empty()).unwrap());
    }

    database.bump_object_last_accessed(object.id).await?;

    if chunks.len() == 1 {
        // single chunk
        let chunk = chunks[0].as_ref().unwrap();
        let remote_file = &chunk.remote_file.0;
        let storage = state.storage().await?;
        // Redirects retain the client's headers, so stream the full object when
        // Range was ignored instead of letting S3 apply it again.
        let prefer_stream = headers.contains_key(header::RANGE) && range.is_none();
        match storage
            .download_file_db(remote_file, prefer_stream, range)
            .await?
        {
            Download::Url(url) => Ok(Redirect::temporary(&url).into_response()),
            Download::AsyncRead(stream) => {
                let stream = ReaderStream::new(stream).map_err(|e| {
                    tracing::error!(%e, "Stream error");
                    e
                });
                let body = Body::from_stream(stream);

                Ok(response.body(body).unwrap())
            }
        }
    } else {
        // reassemble NAR
        fn io_error<E: std::error::Error + Send + Sync + 'static>(e: E) -> IoError {
            IoError::other(e)
        }

        let streamer = |(chunk, range): (ChunkModel, Option<Range<u64>>),
                        storage: Arc<StorageBackendImpl>| async move {
            match storage
                .download_file_db(&chunk.remote_file.0, true, range)
                .await
                .map_err(io_error)?
            {
                Download::Url(_) => Err(IoError::other("URLs not supported for NAR reassembly")),
                Download::AsyncRead(stream) => {
                    let stream: BoxStream<_> = Box::pin(ReaderStream::new(stream));
                    Ok(stream)
                }
            }
        };

        let mut selected_chunks = VecDeque::new();
        let mut offset = 0;
        for chunk in chunks.into_iter().map(Option::unwrap) {
            let start = offset;
            offset += chunk.file_size.unwrap() as u64;
            if offset <= selected.start || start >= selected.end {
                continue;
            }
            let chunk_range = range
                .as_ref()
                .map(|_| selected.start.saturating_sub(start)..selected.end.min(offset) - start);
            selected_chunks.push_back((chunk, chunk_range));
        }
        let storage = state.storage().await?.clone();

        // TODO: Make num_prefetch configurable
        // The ideal size depends on the average chunk size
        let merged = merge_chunks(selected_chunks, streamer, storage, 2).map_err(|e| {
            tracing::error!(%e, "Stream error");
            e
        });
        let body = Body::from_stream(merged);

        Ok(response.body(body).unwrap())
    }
}

pub fn get_router() -> Router {
    Router::new()
        .route("/{cache}/nix-cache-info", get(get_nix_cache_info))
        .route("/{cache}/{path}", get(get_store_path_info))
        .route("/{cache}/nar/{path}", get(get_nar))
}
