pub mod openapi;
pub mod data_store;

#[cfg(not(target_arch = "wasm32"))]
#[cfg(feature = "db_file_json")]
pub mod db_adapter_file;

#[cfg(not(target_arch = "wasm32"))]
#[cfg(any(feature = "postgres", feature = "firebird"))]
pub mod db_adapter_postgres;

#[cfg(not(target_arch = "wasm32"))]
#[cfg(any(feature = "db_file_json", feature = "postgres", feature = "firebird"))]
pub mod entity_manager;

#[cfg(not(target_arch = "wasm32"))]
#[cfg(feature = "http_server")]
pub mod request_filter;

#[cfg(not(target_arch = "wasm32"))]
#[cfg(feature = "http_server")]
pub mod rufs_micro_service;

#[cfg(feature = "client")]
pub mod client;
