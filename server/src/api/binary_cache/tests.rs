use super::*;

use async_compression::tokio::bufread::ZstdEncoder;
use attic::hash::Hash;
use attic::signing::NixKeypair;
use axum::http::Request;
use chrono::Utc;
use http_body_util::BodyExt;
use sea_orm::{ActiveModelTrait, ActiveValue::Set, EntityTrait, IntoActiveModel};
use tempfile::TempDir;
use tokio::io::AsyncReadExt;
use tower::ServiceExt;

use crate::StateInner;
use crate::config::Config;
use crate::database::entity::{Json, cache, chunk, chunkref, nar, object};
use crate::database::migration::{Migrator, MigratorTrait};

const HASH: &str = "00000000000000000000000000000000";
const NAR_URL: &str = "/test/nar/00000000000000000000000000000000.nar";

struct Fixture {
    app: Router,
    state: State,
    _directory: TempDir,
    files: Vec<crate::storage::RemoteFile>,
    bytes: Vec<u8>,
    boundaries: Vec<usize>,
}

impl Fixture {
    async fn new(num_chunks: usize) -> Self {
        let directory = tempfile::tempdir().unwrap();
        let config = include_str!("../../config-template.toml")
            .replace("%database_url%", "sqlite::memory:")
            .replace("%storage_path%", directory.path().to_str().unwrap())
            .replace(
                "token-rs256-secret-base64 = \"%token_rs256_secret_base64%\"",
                "token-hs256-secret-base64 = \"dGVzdC1vbmx5\"",
            );
        let config: Config = toml::from_str(&config).unwrap();
        let state = StateInner::new(config).await;
        let database = state.database().await.unwrap();
        Migrator::up(database, None).await.unwrap();
        let now = Utc::now();
        let cache = cache::ActiveModel {
            name: Set("test".into()),
            keypair: Set(NixKeypair::generate("test").unwrap().export_keypair()),
            is_public: Set(true),
            store_dir: Set("/nix/store".into()),
            priority: Set(40),
            upstream_cache_key_names: Set(Json(vec![])),
            created_at: Set(now),
            ..Default::default()
        }
        .insert(database)
        .await
        .unwrap();

        let inputs: &[&[u8]] = &[
            b"first short chunk",
            b"the second chunk contains a different amount of data",
            b"third chunk: 0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuvwxyz",
        ];
        let inputs = &inputs[..num_chunks];
        let uncompressed = inputs.concat();
        let nar = nar::ActiveModel {
            state: Set(nar::NarState::Valid),
            nar_hash: Set(Hash::sha256_from_bytes(&uncompressed).to_typed_base16()),
            nar_size: Set(uncompressed.len() as i64),
            compression: Set("zstd".into()),
            num_chunks: Set(num_chunks as i32),
            holders_count: Set(0),
            created_at: Set(now),
            ..Default::default()
        }
        .insert(database)
        .await
        .unwrap();

        object::ActiveModel {
            cache_id: Set(cache.id),
            nar_id: Set(nar.id),
            store_path_hash: Set(HASH.into()),
            store_path: Set(format!("/nix/store/{HASH}-test")),
            references: Set(Json(vec![])),
            sigs: Set(Json(vec![])),
            created_at: Set(now),
            ..Default::default()
        }
        .insert(database)
        .await
        .unwrap();

        let storage = state.storage().await.unwrap();
        let mut files = Vec::new();
        let mut bytes = Vec::new();
        let mut boundaries = vec![0];
        for (seq, input) in inputs.iter().enumerate() {
            let mut encoded = Vec::new();
            ZstdEncoder::new(*input)
                .read_to_end(&mut encoded)
                .await
                .unwrap();
            let remote_file = storage
                .upload_file(format!("chunk-{seq}"), &mut encoded.as_slice())
                .await
                .unwrap();
            let chunk = chunk::ActiveModel {
                state: Set(chunk::ChunkState::Valid),
                chunk_hash: Set(Hash::sha256_from_bytes(input).to_typed_base16()),
                chunk_size: Set(input.len() as i64),
                file_hash: Set(Some(Hash::sha256_from_bytes(&encoded).to_typed_base16())),
                file_size: Set(Some(encoded.len() as i64)),
                compression: Set("zstd".into()),
                remote_file: Set(Json(remote_file.clone())),
                remote_file_id: Set(remote_file.remote_file_id()),
                holders_count: Set(0),
                created_at: Set(now),
                ..Default::default()
            }
            .insert(database)
            .await
            .unwrap();
            chunkref::ActiveModel {
                nar_id: Set(nar.id),
                chunk_id: Set(Some(chunk.id)),
                seq: Set(seq as i32),
                ..Default::default()
            }
            .insert(database)
            .await
            .unwrap();
            files.push(remote_file);
            bytes.extend_from_slice(&encoded);
            boundaries.push(bytes.len());
        }

        let app = get_router()
            .layer(axum::middleware::from_fn(
                crate::middleware::init_request_state,
            ))
            .layer(Extension(state.clone()));
        Self {
            app,
            state,
            _directory: directory,
            files,
            bytes,
            boundaries,
        }
    }

    async fn request(&self, method: Method, url: &str, headers: &[(&str, &str)]) -> Response {
        let mut request = Request::builder()
            .method(method)
            .uri(url)
            .header("host", "localhost");
        for (name, value) in headers {
            request = request.header(*name, *value);
        }
        self.app
            .clone()
            .oneshot(request.body(Body::empty()).unwrap())
            .await
            .unwrap()
    }
}

async fn body(response: Response) -> Vec<u8> {
    response
        .into_body()
        .collect()
        .await
        .unwrap()
        .to_bytes()
        .to_vec()
}

#[tokio::test]
async fn conditional_downloads() {
    for num_chunks in [1, 3] {
        let fixture = Fixture::new(num_chunks).await;
        let response = fixture.request(Method::HEAD, NAR_URL, &[]).await;
        let etag = response.headers()[header::ETAG]
            .to_str()
            .unwrap()
            .to_owned();
        for method in [Method::GET, Method::HEAD] {
            for value in [
                etag.clone(),
                format!("W/{etag}"),
                format!("\"other\", W/{etag}"),
                format!("\"other,tag\", W/{etag}"),
                "*".into(),
            ] {
                let response = fixture
                    .request(
                        method.clone(),
                        NAR_URL,
                        &[("if-none-match", &value), ("range", "bytes=99999-")],
                    )
                    .await;
                assert_eq!(
                    response.status(),
                    StatusCode::NOT_MODIFIED,
                    "{method} {value}"
                );
                assert_eq!(response.headers()[header::ETAG], etag);
                assert!(!response.headers().contains_key(header::CONTENT_RANGE));
                // On 304, Content-Length describes the full representation.
                assert_eq!(
                    response.headers()[header::CONTENT_LENGTH],
                    fixture.bytes.len().to_string()
                );
                assert!(body(response).await.is_empty());
            }
        }
        for value in ["\"old\"".into(), format!("{etag}junk"), "invalid".into()] {
            let response = fixture
                .request(Method::GET, NAR_URL, &[("if-none-match", &value)])
                .await;
            assert_eq!(response.status(), StatusCode::OK, "{value}");
            assert_eq!(body(response).await, fixture.bytes);
        }
        let response = fixture
            .request(
                Method::GET,
                NAR_URL,
                &[("if-none-match", "\"old\""), ("range", "bytes=2-7")],
            )
            .await;
        assert_eq!(response.status(), StatusCode::PARTIAL_CONTENT);
        assert_eq!(body(response).await, fixture.bytes[2..8]);
        let response = fixture
            .request(
                Method::GET,
                NAR_URL,
                &[("if-none-match", "\"old\""), ("if-none-match", &etag)],
            )
            .await;
        assert_eq!(response.status(), StatusCode::NOT_MODIFIED);

        for file in &fixture.files {
            fixture
                .state
                .storage()
                .await
                .unwrap()
                .delete_file_db(file)
                .await
                .unwrap();
        }
        let response = fixture
            .request(Method::GET, NAR_URL, &[("if-none-match", &etag)])
            .await;
        assert_eq!(response.status(), StatusCode::NOT_MODIFIED);
        assert!(body(response).await.is_empty());
    }
}

#[tokio::test]
async fn conditional_get_refreshes_last_accessed() {
    for num_chunks in [1, 3] {
        let fixture = Fixture::new(num_chunks).await;
        let database = fixture.state.database().await.unwrap();
        let old = Utc::now() - chrono::Duration::days(30);
        for method in [Method::HEAD, Method::GET] {
            let mut model = object::Entity::find()
                .one(database)
                .await
                .unwrap()
                .unwrap()
                .into_active_model();
            model.created_at = Set(old);
            model.last_accessed_at = Set(Some(old));
            let model = model.update(database).await.unwrap();
            let before = Utc::now() - chrono::Duration::seconds(1);
            let response = fixture
                .request(method.clone(), NAR_URL, &[("if-none-match", "*")])
                .await;
            assert_eq!(response.status(), StatusCode::NOT_MODIFIED);
            assert!(body(response).await.is_empty());
            let accessed = object::Entity::find_by_id(model.id)
                .one(database)
                .await
                .unwrap()
                .unwrap()
                .last_accessed_at
                .unwrap();
            if method == Method::GET {
                assert!(accessed >= before, "Conditional GET must refresh retention");
            } else {
                assert_eq!(accessed, old, "HEAD must not refresh retention");
            }
        }
    }
}

#[tokio::test]
async fn download_sizes_and_ranges() {
    for num_chunks in [1, 3] {
        let fixture = Fixture::new(num_chunks).await;
        let size = fixture.bytes.len();
        let response = fixture.request(Method::GET, NAR_URL, &[]).await;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.headers()[header::CONTENT_LENGTH], size.to_string());
        assert_eq!(response.headers()[header::ACCEPT_RANGES], "bytes");
        let etag = response.headers()[header::ETAG]
            .to_str()
            .unwrap()
            .to_owned();
        assert_eq!(body(response).await, fixture.bytes);

        let response = fixture
            .request(Method::GET, &format!("/test/{HASH}.narinfo"), &[])
            .await;
        assert_eq!(response.status(), StatusCode::OK);
        let text = String::from_utf8(body(response).await).unwrap();
        assert!(
            text.lines().any(|line| line == format!("FileSize: {size}")),
            "{text}"
        );

        let boundary = fixture.boundaries[1];
        for (range, start, end) in [
            ("bytes=0-0".into(), 0, 1),
            ("bytes=2-7".into(), 2, 8),
            ("bytes=3-".into(), 3, size),
            ("bytes=-7".into(), size - 7, size),
            ("bytes=-99999".into(), 0, size),
            ("bytes=5-99999".into(), 5, size),
            (
                format!("bytes={}-{}", boundary - 2, (boundary + 3).min(size - 1)),
                boundary - 2,
                (boundary + 4).min(size),
            ),
            (format!("bytes={}-", size - 1), size - 1, size),
        ] {
            let response = fixture
                .request(Method::GET, NAR_URL, &[("range", &range)])
                .await;
            assert_eq!(response.status(), StatusCode::PARTIAL_CONTENT, "{range}");
            assert_eq!(
                response.headers()[header::CONTENT_LENGTH],
                (end - start).to_string()
            );
            assert_eq!(
                response.headers()[header::CONTENT_RANGE],
                format!("bytes {start}-{}/{size}", end - 1)
            );
            assert_eq!(body(response).await, fixture.bytes[start..end], "{range}");
        }

        for range in [format!("bytes={size}-"), "bytes=-0".into()] {
            let response = fixture
                .request(Method::GET, NAR_URL, &[("range", &range)])
                .await;
            assert_eq!(response.status(), StatusCode::RANGE_NOT_SATISFIABLE);
            assert_eq!(
                response.headers()[header::CONTENT_RANGE],
                format!("bytes */{size}")
            );
            assert!(body(response).await.is_empty());
        }

        for range in ["bytes=4-2", "items=0-1", "bytes=abc", "bytes=0-1,5-6"] {
            let response = fixture
                .request(Method::GET, NAR_URL, &[("range", range)])
                .await;
            assert_eq!(response.status(), StatusCode::OK, "{range}");
            assert!(!response.headers().contains_key(header::CONTENT_RANGE));
            assert_eq!(body(response).await, fixture.bytes);
        }

        let response = fixture
            .request(
                Method::GET,
                NAR_URL,
                &[("range", "bytes=3-"), ("if-range", &etag)],
            )
            .await;
        assert_eq!(response.status(), StatusCode::PARTIAL_CONTENT);
        assert_eq!(body(response).await, fixture.bytes[3..]);
        for validator in [
            "\"old\"".to_owned(),
            format!("W/{etag}"),
            "Wed, 21 Oct 2015 07:28:00 GMT".into(),
        ] {
            let response = fixture
                .request(
                    Method::GET,
                    NAR_URL,
                    &[("range", "bytes=3-"), ("if-range", &validator)],
                )
                .await;
            assert_eq!(response.status(), StatusCode::OK);
            assert_eq!(body(response).await, fixture.bytes);
        }

        // HEAD must not open or download storage objects, and must ignore Range.
        for file in &fixture.files {
            fixture
                .state
                .storage()
                .await
                .unwrap()
                .delete_file_db(file)
                .await
                .unwrap();
        }
        let response = fixture
            .request(Method::HEAD, NAR_URL, &[("range", "bytes=99999-")])
            .await;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.headers()[header::CONTENT_LENGTH], size.to_string());
        assert_eq!(response.headers()[header::ETAG], etag);
        assert!(body(response).await.is_empty());
    }
}

#[tokio::test]
async fn resume_skips_unneeded_chunks() {
    let fixture = Fixture::new(3).await;
    let storage = fixture.state.storage().await.unwrap();
    storage.delete_file_db(&fixture.files[0]).await.unwrap();
    storage.delete_file_db(&fixture.files[2]).await.unwrap();
    let start = fixture.boundaries[1];
    let end = fixture.boundaries[2];
    let range = format!("bytes={start}-{}", end - 1);
    let response = fixture
        .request(Method::GET, NAR_URL, &[("range", &range)])
        .await;
    assert_eq!(response.status(), StatusCode::PARTIAL_CONTENT);
    assert_eq!(body(response).await, fixture.bytes[start..end]);
}

#[tokio::test]
async fn recompression_invalidates_if_range() {
    let fixture = Fixture::new(1).await;
    let response = fixture.request(Method::GET, NAR_URL, &[]).await;
    let old_etag = response.headers()[header::ETAG]
        .to_str()
        .unwrap()
        .to_owned();
    let mut replacement = body(response).await;
    // Adding an empty Zstd frame changes compressed bytes without changing
    // the uncompressed NAR, its hash or the store path URL.
    ZstdEncoder::new(&b""[..])
        .read_to_end(&mut replacement)
        .await
        .unwrap();
    let storage = fixture.state.storage().await.unwrap();
    storage
        .upload_file("chunk-0".into(), &mut replacement.as_slice())
        .await
        .unwrap();
    let database = fixture.state.database().await.unwrap();
    let mut model = chunk::Entity::find()
        .one(database)
        .await
        .unwrap()
        .unwrap()
        .into_active_model();
    model.file_hash = Set(Some(
        Hash::sha256_from_bytes(&replacement).to_typed_base16(),
    ));
    model.file_size = Set(Some(replacement.len() as i64));
    model.update(database).await.unwrap();

    let response = fixture
        .request(
            Method::GET,
            NAR_URL,
            &[("range", "bytes=3-"), ("if-range", &old_etag)],
        )
        .await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_ne!(response.headers()[header::ETAG], old_etag);
    assert_eq!(body(response).await, replacement);
}

#[tokio::test]
async fn conditional_and_range_requests_require_pull_permission() {
    let fixture = Fixture::new(1).await;
    let database = fixture.state.database().await.unwrap();
    let mut cache = cache::Entity::find()
        .one(database)
        .await
        .unwrap()
        .unwrap()
        .into_active_model();
    cache.is_public = Set(false);
    cache.update(database).await.unwrap();
    let response = fixture
        .request(
            Method::GET,
            NAR_URL,
            &[("range", "bytes=99999-"), ("if-none-match", "*")],
        )
        .await;
    assert!(response.status().is_client_error());
    assert_ne!(response.status(), StatusCode::RANGE_NOT_SATISFIABLE);
    assert!(!response.headers().contains_key(header::CONTENT_RANGE));
    assert!(!response.headers().contains_key(header::ETAG));
}

#[tokio::test]
async fn s3_download_and_resume_over_http() {
    use sea_orm::QueryOrder;
    use tokio::net::TcpListener;

    for num_chunks in [1, 3] {
        let fixture = Fixture::new(num_chunks).await;
        let objects: Vec<_> = fixture
            .boundaries
            .windows(2)
            .map(|bounds| fixture.bytes[bounds[0]..bounds[1]].to_vec())
            .collect();
        let bucket = Router::new().route(
            "/test/{name}",
            get(move |Path(name): Path<String>, headers: HeaderMap| {
                let objects = objects.clone();
                async move {
                    let index: usize = name.strip_prefix("chunk-").unwrap().parse().unwrap();
                    let bytes = &objects[index];
                    let mut response = Response::builder().header(header::ETAG, "\"storage-etag\"");
                    // S3 also accepts weak If-Range tags; Attic must enforce
                    // strong comparison before deciding to redirect.
                    if headers.get(header::IF_RANGE).is_none_or(|value| {
                        value == "\"storage-etag\"" || value == "W/\"storage-etag\""
                    }) && let Some(value) = headers.get(header::RANGE)
                    {
                        // The SDK uses canonical, inclusive byte ranges for each object.
                        // Also accept an open end from a redirected HTTP client.
                        let value = value.to_str().unwrap().strip_prefix("bytes=").unwrap();
                        let (start, end) = value.split_once('-').unwrap();
                        let start: usize = start.parse().unwrap();
                        let end: usize = if end.is_empty() {
                            bytes.len() - 1
                        } else {
                            end.parse().unwrap()
                        };
                        response = response.status(StatusCode::PARTIAL_CONTENT).header(
                            header::CONTENT_RANGE,
                            format!("bytes {start}-{end}/{}", bytes.len()),
                        );
                        response
                            .body(Body::from(bytes[start..=end].to_vec()))
                            .unwrap()
                    } else {
                        response.body(Body::from(bytes.clone())).unwrap()
                    }
                }
            }),
        );
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = format!("http://{}", listener.local_addr().unwrap());
        let bucket_task = tokio::spawn(async move { axum::serve(listener, bucket).await.unwrap() });

        let mut config = fixture.state.config.clone();
        config.storage = crate::config::StorageConfig::S3(
            toml::from_str(&format!(
                "region = 'us-east-1'\nbucket = 'test'\nendpoint = '{endpoint}'\n\
             [credentials]\naccess_key_id = 'test'\nsecret_access_key = 'test'\n"
            ))
            .unwrap(),
        );
        let state = StateInner::new(config).await;
        let database = fixture.state.database().await.unwrap();
        state.database.set(database.clone()).unwrap();
        let storage = state.storage().await.unwrap();
        for (seq, model) in chunk::Entity::find()
            .order_by_asc(chunk::Column::Id)
            .all(database)
            .await
            .unwrap()
            .into_iter()
            .enumerate()
        {
            let file = storage
                .make_db_reference(format!("chunk-{seq}"))
                .await
                .unwrap();
            let mut model = model.into_active_model();
            model.remote_file_id = Set(file.remote_file_id());
            model.remote_file = Set(Json(file));
            model.update(database).await.unwrap();
        }
        let app = get_router()
            .layer(axum::middleware::from_fn(
                crate::middleware::init_request_state,
            ))
            .layer(Extension(state));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}{NAR_URL}", listener.local_addr().unwrap());
        let app_task = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

        let client = reqwest::Client::new();
        let response = client.head(&url).send().await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let head_etag = response.headers()[header::ETAG].clone();
        let response = client.get(&url).send().await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.headers()[header::ETAG], head_etag);
        // Keep S3 direct downloads: only metadata should pass through Attic.
        assert_eq!(
            response.url().as_str().starts_with(&endpoint),
            num_chunks == 1
        );
        if num_chunks == 1 {
            assert_eq!(head_etag, "\"storage-etag\"");
        }
        let etag = response.headers()[header::ETAG]
            .to_str()
            .unwrap()
            .to_owned();
        assert_eq!(response.bytes().await.unwrap().as_ref(), fixture.bytes);

        for method in [Method::GET, Method::HEAD] {
            let response = client
                .request(method, &url)
                .header(header::IF_NONE_MATCH, format!("W/{etag}"))
                .header(header::RANGE, "bytes=99999-")
                .send()
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::NOT_MODIFIED);
            assert_eq!(response.headers()[header::ETAG], etag);
            assert!(!response.headers().contains_key(header::CONTENT_RANGE));
            assert!(response.bytes().await.unwrap().is_empty());
        }

        let end = if num_chunks == 1 {
            7
        } else {
            fixture.boundaries[1] + 3
        };
        let range = format!("bytes=2-{end}");
        let response = client
            .get(&url)
            .header(header::RANGE, range)
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::PARTIAL_CONTENT);
        assert_eq!(
            response.headers()[header::CONTENT_RANGE],
            format!("bytes 2-{end}/{}", fixture.bytes.len())
        );
        assert_eq!(
            response.bytes().await.unwrap().as_ref(),
            &fixture.bytes[2..=end]
        );

        // Reassemble an interrupted download using the validator returned by GET.
        let response = client
            .get(&url)
            .header(header::RANGE, "bytes=0-10")
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::PARTIAL_CONTENT);
        let mut resumed = response.bytes().await.unwrap().to_vec();
        let response = client
            .get(&url)
            .header(header::RANGE, "bytes=11-")
            .header(header::IF_RANGE, &etag)
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::PARTIAL_CONTENT);
        assert_eq!(
            response.url().as_str().starts_with(&endpoint),
            num_chunks == 1
        );
        resumed.extend_from_slice(&response.bytes().await.unwrap());
        assert_eq!(resumed, fixture.bytes);

        for validator in [
            format!("W/{etag}"),
            "\"old\"".into(),
            "Wed, 21 Oct 2015 07:28:00 GMT".into(),
        ] {
            let response = client
                .get(&url)
                .header(header::RANGE, "bytes=11-")
                .header(header::IF_RANGE, &validator)
                .send()
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::OK, "{validator}");
            assert_eq!(response.url().as_str(), url);
            assert_eq!(response.headers()[header::ETAG], etag);
            assert_eq!(response.bytes().await.unwrap().as_ref(), fixture.bytes);
        }
        app_task.abort();
        bucket_task.abort();
    }
}
