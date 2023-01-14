use std::{collections::HashMap, fs, io::Error, sync::{RwLock, LockResult, RwLockReadGuard, RwLockWriteGuard}};
use once_cell::sync::Lazy;
use serde_json::Value;
use crate::entity_manager::EntityManager;

static TABLES : Lazy<RwLock<HashMap<String, Value>>> = Lazy::new(|| {
    RwLock::new(HashMap::new())
});

#[derive(Default, Debug)]
pub struct DbAdapterFile {
    //pub openapi    :&'a OpenApi,
    tables: RwLock<HashMap<String, Value>>
}

impl DbAdapterFile {
    pub fn have_table(&self, name: &str) -> bool {
        TABLES.read().unwrap().get(name).is_some()
    }

    pub fn load(&mut self, name: &str, default_rows: &Value) -> Result<(), Error> {
        /*
                var data []byte
                var list []map[string]any

                if data, err = ioutil.ReadFile(fmt.Sprintf("%s.json", name)); err == nil {
                    err = json.Unmarshal(data, &list)
                }

                if fda.fileTables == nil {
                    fda.fileTables = make(map[string][]map[string]any)
                }

                if len(list) == 0 && len(defaultRows) > 0 {
                    err = fda.store(name, defaultRows)
                    list = defaultRows
                }

                fda.fileTables[name] = list
        */
        //println!("{:?}", env::current_dir());
        let file = fs::File::open(format!("{}.json", name))?;
        let json = match serde_json::from_reader(file) {
            Err(error) => {
                println!("[DbAdapterFile.load({})] : {}", name, error);
                default_rows.clone()
            }
            Ok(value) => {
                //println!("[DbAdapterFile.load({})] : {}", name, value);
                value
            }
        };
        TABLES.write().unwrap().insert(name.to_string(), json);
        Ok(())
    }

    fn store(&self, name :&str) -> Result<(), Error> {
        let tables: LockResult<RwLockReadGuard<HashMap<String, Value>>> = TABLES.read();
        let tables: RwLockReadGuard<HashMap<String, Value>> = tables.unwrap();
        let list = tables.get(name).unwrap();
        let path = format!("{}.json", name);
        let contents = serde_json::to_string_pretty(list)?;
        std::fs::write(path, contents)?;
        Ok(())
    }
}

/*
func (fileDbAdapter *FileDbAdapter) Insert(tableName string, obj map[string]any) (map[string]any, error) {
    list, ok := fileDbAdapter.fileTables[tableName]

    if !ok {
        return nil, fmt.Errorf("[FileDbAdapter.Update(name = %s)] : don't find table", tableName)
    }

    if fileDbAdapter.openapi.Components.Schemas[tableName].Properties["id"] != nil {
        id := 0

        for _, item := range list {
            buffer, err := json.Marshal(item)
            itemMap := map[string]any{}
            json.Unmarshal(buffer, &itemMap)

            if value, ok := itemMap["id"]; ok && int(value.(float64)) > id {
                id = int(value.(float64))
            }
        }

        obj["id"] = id + 1
    }

    list = append(list, obj)
    fileDbAdapter.store(tableName, list)
    return obj, nil
}
*/
impl EntityManager for DbAdapterFile {
    /*
        fn find(&self, table_name :String, fields map[string]any, orderBy []string) ([]map[string]any, error) {
            if list, ok := fileDbAdapter.fileTables[tableName]; ok {
                return FilterFind(list, fields)
            }

            return nil, fmt.Errorf("Don't find")
        }
    */

    fn find(self: &Self, table: &str, key: &Value, order_by: &Vec<String>) -> Value {
        println!("[DbAdapterFile.find({}, {})] : {:?}", table, key, order_by);
        TABLES.read().unwrap().get(table).unwrap().clone()
    }
    /*
    func (fileDbAdapter *FileDbAdapter) FindOne(tableName string, key map[string]any) (map[string]any, error) {
        list, ok := fileDbAdapter.fileTables[tableName]

        if !ok {
            return nil, fmt.Errorf("[FileDbAdapter.FindOne] missing table %s", tableName)
        }

        obj, err := FilterFindOne(list, key)

        if err != nil {
            return nil, fmt.Errorf("[FileDbAdapter.FindOne] don't found register in %s with key %s", tableName, key)
        }

        objMap := map[string]any{}
        buffer, _ := json.Marshal(obj)
        err = json.Unmarshal(buffer, &objMap)
        return objMap, err
    }
     */
    fn find_one(self: &Self, table: &str, key: &Value) -> Option<Box<Value>> {
        let tables: LockResult<RwLockReadGuard<HashMap<String, Value>>> = self.tables.read();
        let tables: RwLockReadGuard<HashMap<String, Value>> = tables.unwrap();
        let list = tables.get(table).unwrap().as_array().unwrap();
        let obj = crate::data_store::Filter::find_one(list, key)?;
        println!("[DbAdapterFile.find_one({}, {})] : {:?}", table, key, obj);
        Some(Box::new(obj.clone()))
    }

    fn update<'a>(&self, table_name :&str, key :&Value, obj :&'a Value) -> Result<&'a Value, Error> {
        let tables: LockResult<RwLockReadGuard<HashMap<String, Value>>> = TABLES.read();
        let tables: RwLockReadGuard<HashMap<String, Value>> = tables.unwrap();
        let list = tables.get(table_name).unwrap().as_array().unwrap();
        //let list = TABLES.write().unwrap().get_mut(table_name).unwrap().as_array_mut().unwrap();

        if let Some(pos) = crate::data_store::Filter::find_index(list, key) {
            let tables: LockResult<RwLockWriteGuard<HashMap<String, Value>>> = TABLES.write();
            let mut tables: RwLockWriteGuard<HashMap<String, Value>> = tables.unwrap();
            let list = tables.get_mut(table_name).unwrap().as_array_mut().unwrap();
            list.insert(pos, obj.clone());
            self.store(table_name)?;
            return Ok(obj);
        }

        Err(Error::new(std::io::ErrorKind::NotFound, format!("[FileDbAdapter.Update(name = {}, key = {})] : don't find table", table_name, key)))
    }
}

/*

func (fileDbAdapter *FileDbAdapter) DeleteOne(tableName string, key map[string]any) error {
    list, ok := fileDbAdapter.fileTables[tableName]

    if !ok {
        return fmt.Errorf("[FileDbAdapter.DeleteOne(name = %s)] : don't find table", tableName)
    }

    pos, err := FilterFindIndex(list, key)

    if pos < 0 || err != nil {
        return fmt.Errorf("[FileDbAdapter.DeleteOne(name = %s, key = %s)] fail : %s", tableName, key, err)
    }

    list = append(list[:pos], list[pos+1:]...)
    return fileDbAdapter.store(tableName, list)
}
*/
