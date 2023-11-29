use serde_json::Value;
use anyhow::{Context};

/*
struct DataStore  {
    name:   String,
    schema: &Schema
}

struct DataStoreManager  {
    openapi: &OpenApi
}

impl DataStoreManager {

    fn setSchemas(&self, list: [Schema], openapi: &OpenApi) {
        fn removeBrokenRefs(schema: &Schema, openapi: &OpenApi) {
            for _, field := range schema.Properties {
                if field.Ref != "" {
                    ref := OpenApiGetSchemaName(field.Ref)
                    if _, ok := openapi.Components.Schemas[ref]; !ok {
                        field.Ref = ""
                    }
                }
            }
        }

        self.openapi = openapi;

        if openapi == nil {
            return
        }

        for _, schema := range openapi.Components.Schemas {
            removeBrokenRefs(schema, openapi)
        }

        for _, requestBody := range openapi.Components.RequestBodies {
            for _, mediaTypeObject := range requestBody.Content {
                if mediaTypeObject.Schema.Properties != nil {
                    removeBrokenRefs(mediaTypeObject.Schema, openapi)
                }
            }
        }
    }

    fn DataStoreManagerNew(list: [&Schema], openapi: &OpenApi) -> DataStoreManager {
        let self = &DataStoreManager{};
        self.setSchemas(list, openapi);
        self
    }

}
*/
pub struct Filter;

impl Filter {
    fn check_match_exact(item: &Value, key: &Value) -> Result<bool, Box<dyn std::error::Error>> {
        //println!("[Filter.check_match_exact] item : {}, key : {}", item, key);
        let mut _match = Ok(true);

        for (field_name, expected_value) in key.as_object().unwrap() {
            /*
                        let value = item[fieldName].clone();

                        if expected.is_null() && value.is_null() {
                            continue;
                        }

                        if expected.is_null() || value.is_null() {
                            _match = false;
                            break;
                        }

                        switch expected.(type) {
                        case string:
                            expected = strings.TrimRight(expected.(string), " ")
                        }

                        switch value.(type) {
                        case string:
                            value = strings.TrimRight(value.(string), " ")
                        }
            */

            let item_value = item.get(field_name).context(format!("[check_match_exact] Missing field {} in {}", field_name, item))?;

            let item_value = if let Some(str) = item_value.as_str() {
                str.to_string()
            } else {
                item_value.to_string()
            };

            let expected_value = if let Some(str) = expected_value.as_str() {
                str.to_string()
            } else {
                expected_value.to_string()
            };
            
            if item_value != expected_value {
                _match = Ok(false);
                break;
            }
        }

        _match
    }

    pub fn find<'a>(list: &'a Vec<Value>, filter: &'a Value) -> Result<Vec<&'a Value>, Box<dyn std::error::Error>> {
        let list_out = list.into_iter().filter(|item| Self::check_match_exact(*item, filter).unwrap()).collect();
        Ok(list_out)
    }

    pub fn find_index(list: &Vec<Value>, key: &Value) -> Result<Option<usize>, Box<dyn std::error::Error>> {
        Ok(list.iter().position(|item| Self::check_match_exact(item, key).unwrap()))
    }

    pub fn find_one<'a>(list: &'a Vec<Value>, key: &Value) -> Result<Option<&'a Value>, Box<dyn std::error::Error>> {
        Ok(list.iter().find(|item| Self::check_match_exact(*item, key).unwrap()))
    }
}
