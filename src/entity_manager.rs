use std::{io::Error};

use openapiv3::OpenAPI;
use serde_json::Value;

/*
type EntityManager interface {
    UpdateOpenApi(openapi *OpenApi, options FillOpenApiOptions) error
    CreateTable(name string, schema *Schema) (sql.Result, error)
}

 */

#[tide::utils::async_trait]
pub trait EntityManager {
    async fn insert(&self, openapi: &OpenAPI, table_name :&str, obj: &Value) -> Result<Value, Error>;
    async fn find(&self, openapi: &OpenAPI, table: &str, key: &Value, order_by: &Vec<String>) -> Vec<Value>;
    async fn find_one(&self, openapi: &OpenAPI, table: &str, key: &Value) -> Option<Box<Value>>;
    async fn update(&self, openapi: &OpenAPI, table_name :&str, key :&Value, obj :&Value) -> Result<Value, Error>;
    async fn delete_one(&self, openapi: &OpenAPI, table: &str, key: &Value) -> Result<(), Error>;
}
