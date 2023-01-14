use serde_json::Value;

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
    fn check_match_exact(item: &Value, key: &Value) -> bool {
        let mut _match = true;

        for (field_name, expected) in key.as_object().unwrap() {
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
            if item[field_name].to_string() != expected.to_string() {
                _match = false;
                break;
            }
        }

        _match
    }

    pub fn find<'a>(list: &'a Vec<Value>, filter: &'a Value) -> Vec<&'a Value> {
        let list_out: Vec<&Value> = list.into_iter().filter(|item| Self::check_match_exact(*item, filter)).collect();
        /*
                if filter.as_object().unwrap().is_empty() {
                    return list.clone();
                }

                let list_out = Vec::<Value>::new();

                for item in list.iter() {
                    if Self::check_match_exact(item, filter) {
                        list_out.push(item.clone());
                    }
                }
        */
        list_out
    }

    pub fn find_index(list: &Vec<Value>, key: &Value) -> Option<usize> {
        list.iter().position(|item| Self::check_match_exact(item, key))
    }

    pub fn find_one<'a>(list: &'a Vec<Value>, key: &Value) -> Option<&'a Value> {
        list.iter().find(|item| Self::check_match_exact(*item, key))
    }
}
