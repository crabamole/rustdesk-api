//! Throwaway Postgres databases for tests. One container per test process;
//! every call returns a new empty database on it.
use sqlx::{Connection, Executor, PgConnection};
use testcontainers::runners::AsyncRunner;
use testcontainers::{ContainerAsync, ImageExt};
use testcontainers_modules::postgres::Postgres;
use tokio::sync::OnceCell;
use uuid::Uuid;

struct PgContainer {
    _container: ContainerAsync<Postgres>,
    base_url: String,
}

static PG: OnceCell<PgContainer> = OnceCell::const_new();

async fn container() -> &'static PgContainer {
    PG.get_or_init(|| async {
        let container = Postgres::default()
            .with_tag("17-alpine")
            .start()
            .await
            .expect("failed to start postgres test container (is Docker running?)");
        let port = container.get_host_port_ipv4(5432).await.unwrap();
        PgContainer {
            _container: container,
            base_url: format!("postgres://postgres:postgres@127.0.0.1:{port}"),
        }
    })
    .await
}

/// URL of a new, empty database on the shared test container.
pub async fn fresh_database_url() -> String {
    let pg = container().await;
    let name = format!("test_{}", Uuid::new_v4().as_simple());
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
