#[tokio::main(flavor = "current_thread")]
async fn main() -> anyhow::Result<()> {
    syncstorage_proxy::run().await
}
