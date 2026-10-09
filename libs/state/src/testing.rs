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
/// Includes the image tag so that bumping the tag starts (and reuses) a new
/// container instead of silently reattaching to one running the old image.
const CONTAINER_NAME: &str = "rustdesk-api-test-pg-17-shm";

/// Databases older than this are considered stale and dropped on startup.
const STALE_DATABASE_MAX_AGE_SECS: u64 = 60 * 60;

struct PgContainer {
    _container: ContainerAsync<Postgres>,
    base_url: String,
}

static PG: OnceCell<PgContainer> = OnceCell::const_new();

/// Each test opens its own connection pool (`Database::new`) against the one shared
/// Postgres server; left at the default (`num_cpus::get() * 4`), running tests at full
/// parallelism multiplies that by the number of concurrent tests and can exceed
/// Postgres's own connection limit. Capped low since one test needs only a few.
const TEST_MAX_DATABASE_CONNECTIONS: &str = "5";

async fn container() -> &'static PgContainer {
    PG.get_or_init(|| async {
        if std::env::var_os("MAX_DATABASE_CONNECTIONS").is_none() {
            std::env::set_var("MAX_DATABASE_CONNECTIONS", TEST_MAX_DATABASE_CONNECTIONS);
        }
        let container = Postgres::default()
            .with_tag("17-alpine")
            .with_container_name(CONTAINER_NAME)
            .with_shm_size(512 * 1024 * 1024)
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
///
/// Best-effort: this cleanup races with other test processes doing the same
/// thing against the same shared container (e.g. one process may already
/// have dropped a database another is about to drop), so failures here are
/// logged and skipped rather than propagated — they must never fail the
/// `OnceCell` init and take down every test in the process with them.
async fn drop_stale_databases(base_url: &str) {
    let mut admin = match PgConnection::connect(&format!("{base_url}/postgres")).await {
        Ok(conn) => conn,
        Err(err) => {
            eprintln!("testing::drop_stale_databases: failed to connect, skipping cleanup: {err}");
            return;
        }
    };

    let rows = match admin
        .fetch_all("SELECT datname FROM pg_database WHERE datname LIKE 'test\\_%'")
        .await
    {
        Ok(rows) => rows,
        Err(err) => {
            eprintln!("testing::drop_stale_databases: failed to list databases, skipping cleanup: {err}");
            let _ = admin.close().await;
            return;
        }
    };

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
        if let Err(err) = admin
            .execute(format!("DROP DATABASE IF EXISTS \"{name}\" WITH (FORCE)").as_str())
            .await
        {
            eprintln!("testing::drop_stale_databases: failed to drop \"{name}\", skipping: {err}");
        }
    }

    let _ = admin.close().await;
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
