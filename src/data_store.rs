use serde_json::Value;

pub struct Filter;

impl Filter {
    
    pub fn check_match_exact(item: &Value, key: &Value) -> Result<bool, Box<dyn std::error::Error>> {
        let mut _match = Ok(true);

        for (field_name, expected_value) in key.as_object().ok_or("[check_match_exact] broken key.as_object().")? {
            let item_value = item.get(field_name).ok_or_else(|| {
                format!("[Filter::check_match_exact] Missing field '{}' in {}.", field_name, item)
            })?;

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

}
