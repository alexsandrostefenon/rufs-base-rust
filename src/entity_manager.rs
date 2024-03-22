use async_trait::async_trait;
use openapiv3::{OpenAPI, Schema};
use serde_json::Value;

use crate::openapi::FillOpenAPIOptions;

#[cfg(not(target_arch = "wasm32"))]
#[async_trait]
pub trait EntityManager {
    async fn insert(&self, openapi: &OpenAPI, schema_name :&str, obj: &Value) -> Result<Value, Box<dyn std::error::Error>>;
    async fn find(&self, openapi: &OpenAPI, schema_name: &str, key: &Value, order_by: &Vec<String>) -> Vec<Value>;
    async fn find_one(&self, openapi: &OpenAPI, schema_name: &str, key: &Value) -> Option<Box<Value>>;
    async fn update(&self, openapi: &OpenAPI, schema_name :&str, key :&Value, obj :&Value) -> Result<Value, Box<dyn std::error::Error>>;
    async fn delete_one(&self, openapi: &OpenAPI, schema_name: &str, key: &Value) -> Result<(), Box<dyn std::error::Error>>;
    async fn update_open_api(&mut self, openapi: &mut OpenAPI, options :&mut FillOpenAPIOptions) -> Result<(), Box<dyn std::error::Error>>;
    async fn exec(&self, sql: &str) -> Result<(), Box<dyn std::error::Error>>;
    async fn create_table(&self, schema_name:&str, schema :&Schema) -> Result<(), Box<dyn std::error::Error>>;
}
