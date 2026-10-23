use super::*;

use std::sync::atomic::AtomicBool;

use axum::http::StatusCode;
use axum::response::IntoResponse;
use base64::{Engine, engine::general_purpose::STANDARD};
use futures::TryStreamExt;
use tokio::sync::Notify;

use crate::access::{Token, http::AuthState};
use crate::database::migration::{Migrator, MigratorTrait};
use crate::{RequestStateInner, StateInner};
use attic::cache::CacheName;
use attic::signing::NixKeypair;

struct Upload {
    state: State,
    request: RequestState,
    session_id: Uuid,
    _storage: tempfile::TempDir,
}

impl Upload {
    async fn new(max_connections: u32) -> Self {
        let storage = tempfile::tempdir().unwrap();
        let config = toml::from_str(&format!(
            r#"
            [database]
            url = {:?}
            [storage]
            type = "local"
            path = {:?}
            [upload]
            max-chunk-size = 8
            [chunking]
            nar-size-threshold = 0
            min-size = 64
            avg-size = 128
            max-size = 256
            [jwt.signing]
            token-hs256-secret-base64 = "{}"
            "#,
            format!(
                "sqlite://{}?mode=rwc",
                storage.path().join("db.sqlite").display()
            ),
            storage.path().join("objects"),
            STANDARD.encode(b"upload test key"),
        ))
        .unwrap();
        let state = StateInner::new(config).await;
        let database = sea_orm::Database::connect(state.config.database.url.clone())
            .await
            .unwrap();
        Migrator::up(&database, None).await.unwrap();
        database.close().await.unwrap();
        let mut options = sea_orm::ConnectOptions::new(state.config.database.url.clone());
        options.max_connections(max_connections);
        state
            .database
            .set(sea_orm::Database::connect(options).await.unwrap())
            .unwrap();
        let database = state.database().await.unwrap();
        cache::Entity::insert(cache::ActiveModel {
            name: Set("test".to_string()),
            keypair: Set(NixKeypair::generate("test").unwrap().export_keypair()),
            is_public: Set(false),
            store_dir: Set("/nix/store".to_string()),
            priority: Set(40),
            upstream_cache_key_names: Set(DbJson(vec![])),
            created_at: Set(Utc::now()),
            ..Default::default()
        })
        .exec(database)
        .await
        .unwrap();
        let cache_name = CacheName::new("test".to_string()).unwrap();
        let auth = AuthState::new();
        let mut token = Token::new(
            "test".to_string(),
            &(Utc::now() + chrono::Duration::hours(1)),
        );
        token
            .get_or_insert_permission_mut(cache_name.to_pattern())
            .push = true;
        auth.token.set(token).unwrap();
        let request = Arc::new(RequestStateInner {
            auth,
            api_endpoint: None,
            substituter_endpoint: None,
            host: "localhost".to_string(),
            client_claims_https: false,
            public_cache: AtomicBool::new(false),
        });
        let nar_info = UploadPathNarInfo {
            cache: cache_name,
            store_path_hash: attic::nix_store::StorePathHash::new(
                "00000000000000000000000000000000".to_string(),
            )
            .unwrap(),
            store_path: "/nix/store/00000000000000000000000000000000-test".to_string(),
            references: vec![],
            system: None,
            deriver: None,
            sigs: vec![],
            ca: None,
            nar_hash: Hash::Sha256(Sha256::digest(b"abcdefghijklmnop").into()),
            nar_size: 16,
        };
        let Json(response) = Box::pin(start_upload_session(
            Extension(state.clone()),
            Extension(request.clone()),
            Json(StartUploadPathSessionRequest {
                nar_info,
                chunk_size: Some(8),
            }),
        ))
        .await
        .unwrap();
        let StartUploadPathSessionResponse::Session { session_id, .. } = response else {
            panic!("expected a new session");
        };
        Self {
            state,
            request,
            session_id,
            _storage: storage,
        }
    }

    async fn part(&self, seq: u32, body: impl Into<Body>) -> ServerResult<()> {
        Box::pin(upload_session_part(
            Extension(self.state.clone()),
            Extension(self.request.clone()),
            Path((self.session_id, seq)),
            body.into(),
        ))
        .await
    }

    async fn finalize(&self) -> FinalizeUploadSessionResponse {
        time::timeout(Duration::from_secs(5), async {
            loop {
                let Json(response) = finalize_upload_session(
                    Extension(self.state.clone()),
                    Extension(self.request.clone()),
                    Path(self.session_id),
                )
                .await
                .unwrap();
                if !matches!(response, FinalizeUploadSessionResponse::Pending) {
                    return response;
                }
                time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap()
    }

    async fn saved_parts(&self) -> Vec<upload_session_part::Model> {
        UploadSessionPart::find()
            .order_by_asc(upload_session_part::Column::Seq)
            .all(self.state.database().await.unwrap())
            .await
            .unwrap()
    }
}

#[tokio::test]
async fn repeated_part_preserves_content_and_can_finalize() {
    let upload = Upload::new(1).await;
    upload.part(0, "abcdefgh").await.unwrap();
    let original = upload.saved_parts().await;
    // Retrying after losing the first response must succeed without replacing it.
    upload.part(0, "abcdefgh").await.unwrap();
    for different in ["abcdEfgh", "abcdefg", "abcdefghi", ""] {
        let error = upload.part(0, different).await.unwrap_err();
        assert_eq!(error.into_response().status(), StatusCode::BAD_REQUEST);
    }
    assert_eq!(upload.saved_parts().await, original);
    upload.part(1, "ijklmnop").await.unwrap();

    let parts = upload.saved_parts().await;
    let files = parts
        .iter()
        .map(|p| serde_json::from_str(&p.remote_file).unwrap())
        .collect();
    let saved = stream_remote_files(upload.state.clone(), files)
        .try_collect::<Vec<_>>()
        .await
        .unwrap()
        .concat();
    assert_eq!(saved.as_slice(), b"abcdefghijklmnop");

    let FinalizeUploadSessionResponse::Completed { result } = upload.finalize().await else {
        panic!("expected successful finalization");
    };
    assert_eq!(result.kind, UploadPathResultKind::Uploaded);
}

#[tokio::test]
async fn single_connection_finalization_reports_invalid_content() {
    let upload = Upload::new(1).await;
    upload.part(0, "abcdefgH").await.unwrap();
    upload.part(1, "ijklmnop").await.unwrap();
    assert!(matches!(
        upload.finalize().await,
        FinalizeUploadSessionResponse::Failed { .. }
    ));
}

#[tokio::test]
async fn concurrent_parts_retry_while_pending_and_compare_after_commit() {
    let upload = Upload::new(4).await;
    let entered = Arc::new(Notify::new());
    let resume = Arc::new(Notify::new());
    let body = {
        let entered = entered.clone();
        let resume = resume.clone();
        Body::from_stream(async_stream::stream! {
            entered.notify_one();
            resume.notified().await;
            yield Ok::<_, io::Error>(Bytes::from_static(b"abcdefgh"));
        })
    };
    let writer = upload.part(0, body);
    let concurrent = async {
        entered.notified().await;
        for content in ["abcdefgh", "abcdEfgh"] {
            let error = upload.part(0, content).await.unwrap_err();
            assert_eq!(
                error.into_response().status(),
                StatusCode::SERVICE_UNAVAILABLE
            );
        }
        resume.notify_one();
    };
    time::timeout(Duration::from_secs(5), async {
        let (result, ()) = tokio::join!(writer, concurrent);
        result.unwrap();
    })
    .await
    .unwrap();

    let (same, different) = tokio::join!(upload.part(0, "abcdefgh"), upload.part(0, "abcdEfgh"),);
    same.unwrap();
    assert_eq!(
        different.unwrap_err().into_response().status(),
        StatusCode::BAD_REQUEST
    );
    assert_eq!(upload.saved_parts().await.len(), 1);
    upload.part(0, "abcdefgh").await.unwrap();
}

#[tokio::test]
async fn failed_part_can_be_retried_after_cleanup() {
    let upload = Upload::new(1).await;
    let body = Body::from_stream(futures::stream::iter([
        Ok(Bytes::from_static(b"abcd")),
        Err(io::Error::other("connection lost")),
    ]));
    assert!(upload.part(0, body).await.is_err());
    time::timeout(Duration::from_secs(5), async {
        while !upload.saved_parts().await.is_empty() {
            time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    upload.part(0, "abcdefgh").await.unwrap();
    upload.part(0, "abcdefgh").await.unwrap();
    assert_eq!(upload.saved_parts().await.len(), 1);
}
