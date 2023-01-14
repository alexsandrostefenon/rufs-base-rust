use std::{io::Error};

use serde_json::Value;

/*
type EntityManager interface {
    Connect() error
    Find(tableName string, fields map[string]any, orderBy []string) ([]map[string]any, error)
    FindOne(tableName string, fields map[string]any) (map[string]any, error)
    Insert(tableName string, obj map[string]any) (map[string]any, error)
    Update(tableName string, key map[string]any, obj map[string]any) (map[string]any, error)
    DeleteOne(tableName string, key map[string]any) error
    UpdateOpenApi(openapi *OpenApi, options FillOpenApiOptions) error
    CreateTable(name string, schema *Schema) (sql.Result, error)
}

 */

pub trait EntityManager {
    fn find(self: &Self, table: &str, key: &Value, order_by: &Vec<String>) -> Value;
    fn find_one(self: &Self, table: &str, key: &Value) -> Option<Box<Value>>;
    fn update<'a>(&'a self, table_name :&str, key :&Value, obj :&'a Value) -> Result<&'a Value, Error>;
}
