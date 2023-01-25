use openapiv3::OpenAPI;
use std::{collections::HashMap, fs, io::Error, sync::{RwLock, LockResult, RwLockReadGuard, RwLockWriteGuard, Arc}};
use serde_json::{Value, Number};
use crate::entity_manager::EntityManager;
use crate::openapi::RufsOpenAPI;

#[derive(Debug, Clone, Default)]
pub struct DbAdapterFile<'a> {
    pub openapi    : Option<&'a OpenAPI>,
    tables: Arc<RwLock<HashMap<String, Value>>>
}

impl DbAdapterFile<'_> {
    pub fn have_table(&self, name: &str) -> bool {
        self.tables.read().unwrap().get(name).is_some()
    }

    pub fn load(&mut self, name: &str, default_rows: &Value) -> Result<(), Error> {
        let file = fs::File::open(format!("{}.json", name))?;
        let json = match serde_json::from_reader(file) {
            Err(_error) => {
                default_rows.clone()
            }
            Ok(value) => {
                value
            }
        };
        self.tables.write().unwrap().insert(name.to_string(), json);
        Ok(())
    }

    fn store(&self, name :&str, list: &Value) -> Result<(), Error> {
        let path = format!("{}.json", name);
        let contents = serde_json::to_string_pretty(list)?;
        std::fs::write(path, contents)?;
        Ok(())
    }
}

#[tide::utils::async_trait]
impl EntityManager for DbAdapterFile<'_> {
    fn insert(&self, openapi: &OpenAPI, table_name :&str, obj: &Value) -> Result<Value, Error> {
        let mut obj = obj.clone();
        let tables: LockResult<RwLockWriteGuard<HashMap<String, Value>>> = self.tables.write();
        let mut tables: RwLockWriteGuard<HashMap<String, Value>> = tables.unwrap();
        let list = tables.get(table_name).unwrap().as_array().unwrap();

        //if let Some(openapi) = self.openapi {
            if let Some(_field) = openapi.get_property(table_name, "id") {
                let mut id = 0;
        
                for item in list {
                    if let Some(value) = item["id"].as_u64() {
                        if value > id {
                            id = value;
                        }
                    }
                }
    
                obj["id"] = Value::Number(Number::from(id + 1));
            }
        //}

        let json_array = tables.get_mut(table_name).unwrap();
        let list = json_array.as_array_mut().unwrap();
        list.push(obj.clone());
        self.store(table_name, json_array)?;
        return Ok(obj.clone());
    }

    async fn find(&self, _openapi: &OpenAPI, table: &str, key: &Value, _order_by: &Vec<String>) -> Vec<Value> {
        let tables: LockResult<RwLockReadGuard<HashMap<String, Value>>> = self.tables.read();
        let tables: RwLockReadGuard<HashMap<String, Value>> = tables.unwrap();
        let list = tables.get(table).unwrap().as_array().unwrap();
        let list = crate::data_store::Filter::find(list, key);
        let mut list_out = vec![];

        for item in list {
            list_out.push(item.clone());
        }

        list_out
    }

    async fn find_one(&self, _openapi: &OpenAPI, table: &str, key: &Value) -> Option<Box<Value>> {
        let tables: LockResult<RwLockReadGuard<HashMap<String, Value>>> = self.tables.read();
        let tables: RwLockReadGuard<HashMap<String, Value>> = tables.unwrap();
        let list = tables.get(table).unwrap().as_array().unwrap();
        let obj = crate::data_store::Filter::find_one(list, key)?;
        Some(Box::new(obj.clone()))
    }

    fn update<'a>(&self, _openapi: &OpenAPI, table_name :&str, key :&Value, obj :&'a Value) -> Result<&'a Value, Error> {
        let tables: LockResult<RwLockWriteGuard<HashMap<String, Value>>> = self.tables.write();
        let mut tables: RwLockWriteGuard<HashMap<String, Value>> = tables.unwrap();
        let list = tables.get(table_name).unwrap().as_array().unwrap();

        if let Some(pos) = crate::data_store::Filter::find_index(list, key) {
            let json_array = tables.get_mut(table_name).unwrap();
            let list = json_array.as_array_mut().unwrap();
            list.insert(pos, obj.clone());
            self.store(table_name, json_array)?;
            return Ok(obj);
        }

        Err(Error::new(std::io::ErrorKind::NotFound, format!("[FileDbAdapter.Update(name = {}, key = {})] : don't find table", table_name, key)))
    }

    fn delete_one(&self, _openapi: &OpenAPI, table_name: &str, key: &Value) -> Result<(), Error> {
        let tables: LockResult<RwLockWriteGuard<HashMap<String, Value>>> = self.tables.write();
        let mut tables: RwLockWriteGuard<HashMap<String, Value>> = tables.unwrap();
        let list = tables.get(table_name).unwrap().as_array().unwrap();

        if let Some(pos) = crate::data_store::Filter::find_index(list, key) {
            let json_array = tables.get_mut(table_name).unwrap();
            let list = json_array.as_array_mut().unwrap();
            list.remove(pos);
            self.store(table_name, json_array)?;
            return Ok(());
        }

        Err(Error::new(std::io::ErrorKind::NotFound, format!("[FileDbAdapter.Update(name = {}, key = {})] : don't find table", table_name, key)))
    }
}
