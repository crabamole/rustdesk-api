//! Throwaway Postgres databases for tests. One shared, reused container across
//! test process runs; every call returns a new empty database on it.
use std::time::{SystemTime, UNIX_EPOCH};

use sqlx::{Connection, Executor, PgConnection, Row};
use testcontainers::runners::AsyncRunner;
use testcontainers::{ContainerAsync, ImageExt, ReuseDirective};
use testcontainers_modules::postgres::Postgres;
use tokio::sync::OnceCell;
use uuid::Uuid;

/// Name of the shared, reused Postgres test container. Fixed so that
/// `ReuseDirective::Always` can find and reattach to it across process runs,
/// instead of each test binary invocation starting (and leaking) its own.
const CONTAINER_NAME: &str = "sctgdesk-api-server-test-pg";

/// Databases older than this are considered stale and dropped on startup.
const STALE_DATABASE_MAX_AGE_SECS: u64 = 60 * 60;

struct PgContainer {
    _container: ContainerAsync<Postgres>,
    base_url: String,
}

static PG: OnceCell<PgContainer> = OnceCell::const_new();

async fn container() -> &'static PgContainer {
    PG.get_or_init(|| async {
        let container = Postgres::default()
            .with_tag("17-alpine")
            .with_container_name(CONTAINER_NAME)
            .with_reuse(ReuseDirective::Always)
            .start()
            .await
            .expect("failed to start postgres test container (is Docker running?)");
        let port = container.get_host_port_ipv4(5432).await.unwrap();
        let pg = PgContainer {
            _container: container,
            base_url: format!("postgres://postgres:postgres@127.0.0.1:{port}"),
        };
        drop_stale_databases(&pg.base_url).await;
        pg
    })
    .await
}

/// Drops test databases created more than [`STALE_DATABASE_MAX_AGE_SECS`] ago.
/// Runs once per process, right after the shared container comes up, so a
/// long-lived reused container doesn't accumulate one database per test run
/// forever.
async fn drop_stale_databases(base_url: &str) {
    let mut admin = PgConnection::connect(&format!("{base_url}/postgres"))
        .await
        .unwrap();

    let rows = admin
        .fetch_all("SELECT datname FROM pg_database WHERE datname LIKE 'test\\_%'")
        .await
        .unwrap();

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();

    for row in rows {
        let name: String = row.get("datname");
        let Some(created_at) = parse_created_at(&name) else {
            continue;
        };
        if now.saturating_sub(created_at) < STALE_DATABASE_MAX_AGE_SECS {
            continue;
        }
        admin
            .execute(format!("DROP DATABASE IF EXISTS \"{name}\" WITH (FORCE)").as_str())
            .await
            .unwrap();
    }

    admin.close().await.unwrap();
}

/// Parses the unix-seconds timestamp embedded in a `test_<unix_seconds>_<uuid_simple>`
/// database name. Returns `None` for names that don't match that shape.
fn parse_created_at(database_name: &str) -> Option<u64> {
    let rest = database_name.strip_prefix("test_")?;
    let (timestamp, _uuid) = rest.split_once('_')?;
    timestamp.parse().ok()
}

/// URL of a new, empty database on the shared test container.
pub async fn fresh_database_url() -> String {
    let pg = container().await;
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let name = format!("test_{now}_{}", Uuid::new_v4().as_simple());
    let mut admin = PgConnection::connect(&format!("{}/postgres", pg.base_url))
        .await
        .unwrap();
    admin
        .execute(format!("CREATE DATABASE \"{name}\"").as_str())
        .await
        .unwrap();
    admin.close().await.unwrap();
    format!("{}/{}", pg.base_url, name)
}
