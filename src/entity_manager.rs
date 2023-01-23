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
    fn insert(&self, openapi: &OpenAPI, table_name :&str, obj: &Value) -> Result<Value, Error>;
    async fn find(self: &Self, table: &str, key: &Value, order_by: &Vec<String>) -> Vec<Value>;
    fn find_one(self: &Self, table: &str, key: &Value) -> Option<Box<Value>>;
    fn update<'a>(&'a self, table_name :&str, key :&Value, obj :&'a Value) -> Result<&'a Value, Error>;
    fn delete_one(self: &Self, table: &str, key: &Value) -> Result<(), Error>;
}
