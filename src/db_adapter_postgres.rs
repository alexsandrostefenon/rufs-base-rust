use std::{io::Error};

use serde_json::{Value};

use crate::entity_manager::EntityManager;

#[derive(Clone, Default, Debug)]
pub struct DbAdapterPostgres {
    //pub openapi    :&'a OpenApi,
    tmp: Value,
}

impl EntityManager for DbAdapterPostgres {
    fn find_one(self: &Self, table: &str, key: &Value) -> Option<Box<Value>> {
        println!("[DbAdapterPostgres.find_one({}, {})]", table, key);
        None
    }

    fn find(self: &Self, table: &str, key: &Value, order_by: &Vec<String>) -> Value {
        println!("[DbAdapterPostgres.find({}, {}, {})]", table, key, order_by.len());
        Value::Array(vec![])
    }

    fn update<'a>(&'a self, table_name :&str, key :&Value, obj :&'a Value) -> Result<&'a Value, Error> {
        println!("[DbAdapterPostgres.find({}, {}, {})]", table_name, key, obj.to_string());
        Ok(&self.tmp)
    }
}
