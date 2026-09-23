fn main() {
    // sqlx::migrate! embeds migrations at compile time; rebuild when they change.
    println!("cargo:rerun-if-changed=migrations");
}
