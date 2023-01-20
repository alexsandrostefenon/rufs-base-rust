use std::{io::Error};

use openapiv3::OpenAPI;
use serde_json::{Value, Number, json};
use postgres::{Client, NoTls, types::Type, Row};

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
    fn get_json(&self, row: &Row) -> Value {
        let mut obj = json!({});

        for idx in 0..row.len() {
            let column = &row.columns()[idx];
            let name = column.name();
            let typ = column.type_();

            let value : Value = match *typ {
                Type::VARCHAR => Value::String(row.get(idx)),
                Type::INT4 => Value::Number(Number::from(row.get::<usize, i32>(idx))),
                Type::INT8 => Value::Number(Number::from(row.get::<usize, i64>(idx))),
                Type::JSONB => row.get(idx),
                Type::JSONB_ARRAY => {
                    let list = row.get::<_, Vec<Value>>(idx);
                    Value::Array(list)
                },
                _ => row.get(idx)
            };

            obj[name] = value;
        }

        obj
    }

    fn get_json_list(&self, rows: &Vec<Row>) -> Vec<Value> {
        let mut list = vec![];

        for row in rows {
            list.push(self.get_json(row));
        }

        list
    }

    pub fn connect(&self, uri :&str) -> Result<(), Error> {
        let mut client = Client::connect(uri, NoTls).unwrap();
        let list = client.query("SELECT * FROM rufs_user", &[]).unwrap();
        let list_out = self.get_json_list(&list);
        println!("{:?}", list_out);
        Ok(())
    }
}
