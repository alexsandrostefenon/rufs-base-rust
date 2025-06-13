use async_trait::async_trait;
use openapiv3::{OpenAPI, Schema};
use std::{collections::HashMap, fs, sync::{RwLock, LockResult, RwLockReadGuard, RwLockWriteGuard, Arc}};
use serde_json::{json, Number, Value};
#[cfg(not(target_arch = "wasm32"))]
use crate::entity_manager::EntityManager;
use crate::openapi::RufsOpenAPI;
use crate::openapi::FillOpenAPIOptions;

#[derive(Debug, Clone, Default)]
pub struct DbAdapterFile<'a> {
    pub openapi    : Option<&'a OpenAPI>,
    tables: Arc<RwLock<HashMap<String, Value>>>
}

impl DbAdapterFile<'_> {
    pub fn have_table(&self, name: &str) -> bool {
        self.tables.read().unwrap().get(name).is_some()
    }

    pub fn load(&mut self, name: &str, default_rows: &Value) -> Result<(), Box<dyn std::error::Error>> {
        let file_name = format!("{}.json", name);
        let json = match fs::File::open(file_name) {
            Ok(file) => {
                match serde_json::from_reader(file) {
                    Err(_error) => {
                        default_rows.clone()
                    }
                    Ok(value) => {
                        value
                    }
                }
            },
            Err(_err) => default_rows.clone(),
        };

        self.tables.write().unwrap().insert(name.to_string(), json);
        Ok(())
    }

    fn store(&self, name :&str) -> Result<(), Box<dyn std::error::Error>> {
        let empty_list = json!([]);
        let table = self.tables.read().unwrap();
        let list = table.get(name).unwrap_or(&empty_list);
        let path = format!("{}.json", name);
        let contents = serde_json::to_string_pretty(list)?;
        std::fs::write(path, contents)?;
        Ok(())
    }
}

#[cfg(not(target_arch = "wasm32"))]
#[async_trait]
impl EntityManager for DbAdapterFile<'_> {
    async fn insert(&self, openapi: &OpenAPI, _db_schema: &str, openapi_schema :&str, obj: &Value) -> Result<Value, Box<dyn std::error::Error>> {
        let mut obj = obj.clone();

        {
            let tables = self.tables.read().unwrap();

            if let Some(_field) = openapi.get_property(openapi_schema, "id") {
                let list = tables.get(openapi_schema).unwrap().as_array().unwrap();
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
        }

        {
            let mut tables = self.tables.write().unwrap();
            let json_array = tables.get_mut(openapi_schema).unwrap();
            let list = json_array.as_array_mut().unwrap();
            list.push(obj.clone());
        }

        self.store(openapi_schema)?;
        return Ok(obj.clone());
    }

    async fn find(&self, _openapi: &OpenAPI, _db_schema: &str, openapi_schema: &str, key: &Value, _order_by: &Vec<String>) -> Result<Vec<Value>, Box<dyn std::error::Error>> {
        let tables: LockResult<RwLockReadGuard<HashMap<String, Value>>> = self.tables.read();
        let tables: RwLockReadGuard<HashMap<String, Value>> = tables.unwrap();
        let list = tables.get(openapi_schema).unwrap().as_array().unwrap();
        let list = crate::data_store::Filter::find(list, key).unwrap();
        let mut list_out = vec![];

        for item in list {
            list_out.push(item.clone());
        }

        Ok(list_out)
    }

    async fn find_one(&self, _openapi: &OpenAPI, _db_schema: &str, openapi_schema: &str, key: &Value) -> Result<Option<Box<Value>>, Box<dyn std::error::Error>> {
        let tables: LockResult<RwLockReadGuard<HashMap<String, Value>>> = self.tables.read();
        let tables: RwLockReadGuard<HashMap<String, Value>> = tables.unwrap();
        let table = tables.get(openapi_schema).ok_or_else(|| format!("Missing table {}.", openapi_schema))?;

        let list = table.as_array().ok_or_else(|| {
            println!("Raw table {} content :\n{}", openapi_schema, serde_json::to_string_pretty(table).unwrap());
            format!("Table {} is not array.", openapi_schema)
        })?;

        let Some(index) = crate::data_store::Filter::find_index(list, key)? else {
            return Ok(None);
        };

        let obj = list.get(index).ok_or("[DbAdapterFile.find_one] Broken get item.")?;
        Ok(Some(Box::new(obj.clone())))
    }

    async fn update(&self, _openapi: &OpenAPI, _db_schema: &str, openapi_schema :&str, key :&Value, obj :&Value) -> Result<Value, Box<dyn std::error::Error>> {
        {
            let tables: LockResult<RwLockWriteGuard<HashMap<String, Value>>> = self.tables.write();
            let mut tables: RwLockWriteGuard<HashMap<String, Value>> = tables.unwrap();
            let list = tables.get(openapi_schema).unwrap().as_array().unwrap();
    
            if let Some(pos) = crate::data_store::Filter::find_index(list, key).unwrap() {
                let json_array = tables.get_mut(openapi_schema).unwrap();
                let list = json_array.as_array_mut().unwrap();
                list.insert(pos, obj.clone());
            } else {
                return Err(format!("[FileDbAdapter.Update(name = {}, key = {})] : don't find table", openapi_schema, key))?;
            }
        }

        self.store(openapi_schema)?;
        return Ok(obj.clone());
    }

    async fn delete_one(&self, _openapi: &OpenAPI, _db_schema: &str, openapi_schema: &str, key: &Value) -> Result<(), Box<dyn std::error::Error>> {
        {
            let tables: LockResult<RwLockWriteGuard<HashMap<String, Value>>> = self.tables.write();
            let mut tables: RwLockWriteGuard<HashMap<String, Value>> = tables.unwrap();
            let list = tables.get(openapi_schema).unwrap().as_array().unwrap();
    
            if let Some(pos) = crate::data_store::Filter::find_index(list, key).unwrap() {
                let json_array = tables.get_mut(openapi_schema).unwrap();
                let list = json_array.as_array_mut().unwrap();
                list.remove(pos);
            } else {
                return Err(format!("[FileDbAdapter.Update(name = {}, key = {})] : don't find table", openapi_schema, key))?;
            }
        }

        self.store(openapi_schema)?;
        return Ok(());
    }

    async fn update_open_api(&mut self, _openapi: &mut OpenAPI, _options :&mut FillOpenAPIOptions) -> Result<(), Box<dyn std::error::Error>> {
        Ok(())
    }

    async fn exec(&self, _sql: &str) -> Result<(), Box<dyn std::error::Error>> {
        Ok(())
    }   

    async fn create_table(&self, _db_schema: &str, _openapi_schema: &str, _schema :&Schema) -> Result<(), Box<dyn std::error::Error>> {
        Ok(())
    }

	async fn check_schema(&self, _db_schema: &str, _user_id: &str, _user_password: &str) -> Result<(), Box<dyn std::error::Error>> {
        // TODO : clonar as tabelas que começam por "public."
		Ok(())
	}

}
