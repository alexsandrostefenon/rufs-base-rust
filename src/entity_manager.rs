use std::{io::Error};

use serde_json::Value;

/*
type EntityManager interface {
    Connect() error
    UpdateOpenApi(openapi *OpenApi, options FillOpenApiOptions) error
    CreateTable(name string, schema *Schema) (sql.Result, error)
}

 */

pub trait EntityManager {
    fn insert(&self, table_name :&str, obj: &Value) -> Result<Value, Error>;
    fn find(self: &Self, table: &str, key: &Value, order_by: &Vec<String>) -> Vec<Value>;
    fn find_one(self: &Self, table: &str, key: &Value) -> Option<Box<Value>>;
    fn update<'a>(&'a self, table_name :&str, key :&Value, obj :&'a Value) -> Result<&'a Value, Error>;
    fn delete_one(self: &Self, table: &str, key: &Value) -> Result<(), Error>;
}
