use std::{io::Error};

use openapiv3::OpenAPI;
use serde_json::{Value};
use postgres::{Client, NoTls};

use crate::entity_manager::EntityManager;

#[derive(Clone, Default, Debug)]
pub struct DbAdapterPostgres {
    //pub openapi    :&'a OpenApi,
    //client: Client,
    tmp: Value,
}

impl EntityManager for DbAdapterPostgres {
    fn insert(&self, _openapi: &OpenAPI, table_name :&str, obj :&Value) -> Result<Value, Error> {
        println!("[DbAdapterPostgres.find({}, {})]", table_name, obj.to_string());
        Ok(obj.clone())
    }

    fn find_one(self: &Self, table: &str, key: &Value) -> Option<Box<Value>> {
        println!("[DbAdapterPostgres.find_one({}, {})]", table, key);
        None
    }

    fn find(self: &Self, table: &str, key: &Value, order_by: &Vec<String>) -> Vec<Value> {
        println!("[DbAdapterPostgres.find({}, {}, {})]", table, key, order_by.len());
        vec![]
    }

    fn update<'a>(&'a self, table_name :&str, key :&Value, obj :&'a Value) -> Result<&'a Value, Error> {
        println!("[DbAdapterPostgres.find({}, {}, {})]", table_name, key, obj.to_string());
        Ok(&self.tmp)
    }

    fn delete_one(self: &Self, table_name: &str, key: &Value) -> Result<(), Error> {
        println!("[DbAdapterPostgres.delete_one({}, {})]", table_name, key);
        Ok(())
    }
}

impl DbAdapterPostgres {
    pub fn connect(&self, _uri :&str) -> Result<(), Error> {
        let mut client = Client::connect("host=localhost user=postgres", NoTls).unwrap();
        let _x = client.query("SELECT id, name, data FROM person", &[]);
        Ok(())
    }
}