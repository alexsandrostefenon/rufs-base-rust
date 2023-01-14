use crate::{micro_service_server::IMicroServiceServer, rufs_micro_service::{RufsMicroService}};

pub mod data_store;
pub mod db_adapter_file;
pub mod db_adapter_postgres;
pub mod entity_manager;
pub mod micro_service_server;
pub mod openapi;
pub mod request_filter;
pub mod rufs_micro_service;

#[async_std::main]
async fn main() -> tide::Result<()> {
    let mut rufs = RufsMicroService::default();
    rufs.micro_service_server.serve_static_paths = vec![
        std::path::Path::new("rufs-nfe-es6/webapp").to_path_buf(),
        std::path::Path::new("rufs-crud-es6/webapp").to_path_buf(),
        std::path::Path::new("rufs-base-es6/webapp").to_path_buf(),
    ];
    rufs.init()?;
    let mut http_server = tide::new();

    http_server.at("/websocket").with(tide_websockets::WebSocket::new(|_request, mut stream| async move {
        while let Some(Ok(tide_websockets::Message::Text(input))) = async_std::stream::StreamExt::next(&mut stream).await {
            let _token: String = input.chars().rev().collect();
            //rufs.ws_server_connections.insert(token, stream);
        }

        Ok(())
    }));

    //let lock = Arc::new(Mutex::new(rufs as Box<(dyn IMicroServiceServer + Sync + std::marker::Send + 'static)>));
    //let lock2 = Arc::clone(&lock);
    let listen = format!("127.0.0.1:{}", rufs.micro_service_server.port);
    http_server.with(rufs);
    http_server.listen(listen).await?;
    Ok(())
}
