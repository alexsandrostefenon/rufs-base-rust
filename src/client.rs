use chrono::{DateTime, Datelike, Days, Local, Months, NaiveDateTime, TimeZone, Timelike, Utc};
use convert_case::Casing;
use indexmap::IndexMap;
use openapiv3::{OpenAPI, ReferenceOr, Schema, SchemaKind, StringFormat, Type, VariantOrUnknownOrEmpty};
use regex;
use reqwest::Method;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{cmp::Ordering, collections::HashMap, vec};

//#[cfg(target_arch = "wasm32")]
//use web_log::println;

#[derive(Debug, PartialEq, Clone, Copy, Default, Deserialize, Serialize)]
pub enum FieldSortType {
    #[default]
    None,
    Asc,
    Desc,
}

#[derive(Debug, Clone, Copy, Default, Deserialize, Serialize)]
pub struct FieldSort {
    sort_type: FieldSortType,
    order_index: i64,
    table_visible: bool,
    hidden: bool,
}

#[derive(Default)]
struct HttpRestRequest {
    server_url_api: String,
    // message_working :String,
    // message_error :String,
    //http_error: String,
    token: Option<String>,
}

impl HttpRestRequest {
    fn new(server_url: &str) -> Self {
        //if url.endsWith("/") == true) url = url.substring(0, url.length-1);
        // TODO : change "rest" by openapi.server.base
        Self {
            server_url_api: format!("{}/{}", server_url, "rest"),
            ..Default::default()
        }
    }
    /*
       async fn login_basic(&mut self, path :&str, username :&str, password :&str) -> Result<LoginResponseClient, Box<std::error::Error>> {
           let client = reqwest::Client::new();
           let resp = client.post(&format!("{}/{}", self.url, path)).basic_auth(username, Some(password)).send().await?;

           if resp.status() != reqwest::StatusCode::OK {
               println!("[login_basic] : {:?}", resp);
           }

           let login_response_client = resp.json::<LoginResponseClient>().await?;
           self.token = Some(login_response_client.jwt_header.clone());
           Ok(login_response_client)
       }
    */
    async fn request_text(&self, path: &str, method: Method, params: &Value, data_out: &Value) -> Result<String, Box<dyn std::error::Error>> {
        let query_string = serde_qs::to_string(params).unwrap();

        let url = if query_string.len() > 0 {
            format!("{}{}?{}", self.server_url_api, path, query_string)
        } else {
            format!("{}{}", self.server_url_api, path)
        };

        let request = match method {
            Method::POST => reqwest::Client::new().post(&url).json(&data_out),
            Method::PUT => reqwest::Client::new().put(&url).json(&data_out),
            _ => reqwest::Client::new().request(method.clone(), &url)
        };

        let request = if let Some(token) = &self.token { request.bearer_auth(token) } else { request };

        println!("[HttpRestRequest::request_text] : waiting for {} {} ...", method, url);

        let response = match request.send().await {
            Ok(response) => response,
            Err(err) => {
                println!("[request_text] Error : {}", err);
                return Err(Box::new(err) as Box<dyn std::error::Error>);
            }
        };

        let status = response.status();
        let data_in = response.text().await?;
        println!("[HttpRestRequest::request_text] : ... returned {} from {}", status, url);

        if status != reqwest::StatusCode::OK {
            return Err(data_in)?;
        }

        Ok(data_in)
    }

    async fn request(&self, path: &str, method: Method, params: &Value, data_out: &Value) -> Result<Value, Box<dyn std::error::Error>> {
        let data_in = self.request_text(path, method, params, &data_out).await?;
        Ok(serde_json::from_str(&data_in)?)
    }

    async fn login(&self, path: &str, username: &str, password: &str) -> Result<LoginResponseClient, Box<dyn std::error::Error>> {
        let data_out = json!({"user": username, "password": password});
        let data_in = self.request_text(path, Method::POST, &Value::Null, &data_out).await?;
        let login_response_client = serde_json::from_str::<LoginResponseClient>(&data_in)?;
        Ok(login_response_client)
    }

    async fn save(&self, path: &str, item_send: &Value) -> Result<Value, Box<dyn std::error::Error>> {
        self.request(path, Method::POST, &Value::Null, item_send).await
    }

    async fn update(&self, path: &str, params: &Value, item_send: &Value) -> Result<Value, Box<dyn std::error::Error>> {
        self.request(path, Method::PUT, params, item_send).await
    }

    async fn query(&self, path: &str, params: &Value) -> Result<Value, Box<dyn std::error::Error>> {
        self.request(path, Method::GET, params, &Value::Null).await
    }

    async fn get(&self, path: &str, params: &Value) -> Result<Value, Box<dyn std::error::Error>> {
        self.request(path, Method::GET, params, &Value::Null).await
    }

    async fn remove(&self, path: &str, params: &Value) -> Result<Value, Box<dyn std::error::Error>> {
        self.request(path, Method::DELETE, params, &Value::Null).await
    }
    /*
        async fn patch(&self, path :&str, item_send :&Value) -> Result<Value, anyhow::Error> {
            self.request(path, Method::PATCH, &Value::Null, item_send).await
        }
    */
}

#[derive(PartialEq, Clone, Copy, Debug, Default)]
pub enum DataViewProcessAction {
    New,
    Edit,
    View,
    #[default]
    Search,
    Filter,
    Aggregate,
    Sort,
}

impl std::fmt::Display for DataViewProcessAction {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            DataViewProcessAction::New => write!(f, "new"),
            DataViewProcessAction::Edit => write!(f, "edit"),
            DataViewProcessAction::View => write!(f, "view"),
            DataViewProcessAction::Search => write!(f, "search"),
            DataViewProcessAction::Filter => write!(f, "filter"),
            DataViewProcessAction::Aggregate => write!(f, "aggregate"),
            DataViewProcessAction::Sort => write!(f, "sort"),
        }
    }
}

impl std::convert::From<&str> for DataViewProcessAction {
    fn from(value: &str) -> Self {
        match value {
            "new" => DataViewProcessAction::New,
            "edit" => DataViewProcessAction::Edit,
            "view" => DataViewProcessAction::View,
            _ => DataViewProcessAction::Search,
        }
    }
}

pub struct Service {
    schema_name: String,
    path: String,
    method_response: String,
    short_description_list: Vec<String>,
    primary_keys: Vec<String>,
    list: Vec<Value>,
    list_str: Vec<String>,
    map_list: IndexMap<String, usize>,
}

impl Service {
    pub fn new(openapi: &OpenAPI, path: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let (short_description_list, primary_keys, _, method_response) = openapi.get_properties_with_extensions(path, &["get", "post", "put", "delete"], &SchemaPlace::Response)?;

        Ok(Self {
            path: path.to_string(),
            schema_name: path[1..].to_string().to_case(convert_case::Case::Camel),
            method_response: method_response.to_string(),
            primary_keys,
            short_description_list,
            list: vec![],
            list_str: vec![],
            map_list: IndexMap::default()
        })
    }

    pub fn get_primary_key(&self, obj: &Value) -> Option<Value> {
        let mut ret = json!({});

        for field_name in &self.primary_keys {
            let value = obj.get(field_name)?;
            ret[field_name] = value.clone();
        }

        Some(ret)
    }

    pub fn get_primary_key_hash(&self, obj: &Value) -> Result<String, Box<dyn std::error::Error>> {
        let mut list = Vec::with_capacity(self.primary_keys.len());

        for field_name in &self.primary_keys {
            let value = obj.get(field_name).ok_or_else(|| {
                format!("[get_primary_key_hash] Missing primary_key field {} in item :\n{}", field_name, obj)
            })?;
            list.push(value.to_string());
        }

        Ok(list.join("-"))
    }

    async fn query_remote(&self, server_connection: &ServerConnection, params: &Value) -> Result<(IndexMap<String, usize>, Vec<Value>, Vec<String>), Box<dyn std::error::Error>> {
        fn build_list_str(service: &Service, server_connection: &ServerConnection, list: &Vec<Value>) -> Result<(IndexMap<String, usize>, Vec<String>), Box<dyn std::error::Error>> {
            let mut list_str = Vec::with_capacity(list.len());
            let mut map_list = IndexMap::with_capacity(list.len());
            let mut index = 0;
    
            for item in list {
                let str = service.build_item_str(server_connection, item)?;
                let primary_key_hash = service.get_primary_key_hash(item)?;
                map_list.insert(primary_key_hash, index);
                list_str.push(str);
                index += 1;
            }
    
            Ok((map_list, list_str))
        }
    
        let access = server_connection.login_response.roles.iter().find(|role| role.path == self.path).ok_or_else(|| format!("query_remote broken role."))?.mask;

        if access & 1 != 0 {
            //console.log("[ServerConnection] loading", service.label, "...");
            //callback_partial("loading... " + service.label);
            let value = server_connection.http_rest.query(&self.path, params).await?;

            let list = match value {
                Value::Array(list) => list,
                Value::Null => todo!(),
                Value::Bool(_) => todo!(),
                Value::Number(_) => todo!(),
                Value::String(_) => todo!(),
                Value::Object(_) => todo!(),
            };

            let (map_list, list_str) = build_list_str(self, server_connection, &list)?;
            /*
            let dependents = server_connection.login_response.openapi.get_dependents(&self.name, false);
            let mut list_processed = vec![];
            // também atualiza a lista de nomes de todos os serviços que dependem deste
            for item in &dependents {
                if list_processed.contains(&item.schema) == false {
                    if let Some(service) = server_connection.services.get_mut(&item.schema) {
                        service.list_str = service.build_list_str(server_connection);
                        list_processed.push(item.schema.clone());
                    }
                }
            }
            */
            return Ok((map_list, list, list_str));
        }

        Ok((IndexMap::default(), vec![], vec![]))
    }

    pub fn find_pos(&self, primary_key: &Value) -> Result<Option<usize>, Box<dyn std::error::Error>> {
        let primary_key = self.get_primary_key_hash(primary_key)?;
        Ok(self.map_list.get(&primary_key).copied())
    }

    fn build_field_str(server_connection: &ServerConnection, parent_name: &Option<String>, schema_name: &str, field_name: &str, obj: &Value) -> Result<String, Box<dyn std::error::Error>> {
        fn build_field_reference(server_connection: &ServerConnection, schema_name: &str, field_name: &str, obj: &Value, _reference: &String) -> Result<String, Box<dyn std::error::Error>> {
            let item = server_connection.login_response.openapi.get_primary_key_foreign(schema_name, field_name, obj).unwrap().unwrap();

            if item.valid == false {
                return Ok("".to_string());
            }

            let service = server_connection.service_map.get(&item.schema).ok_or_else(|| format!("[build_field_reference] Don't found service {}", item.schema))?;
            let primary_key = item.primary_key;
/*
            let debug_now = std::time::SystemTime::now();
 */
            let pos = service.find_pos(&primary_key)?.ok_or_else(|| format!("[build_field_reference] Don't found item for primary_key {}.\nOptions : {:?}", primary_key, service.map_list))?;
/*
            if schema_name == "request" {
                println!("{:9} [DEBUG - build_field_str] {}.{} : {}.", debug_now.elapsed()?.as_millis(), schema_name, field_name, primary_key);
            }
 */
            let str = service.list_str[pos].clone();
            Ok(str)
        }

        let value = if let Some(value) = obj.get(field_name) {
            match value {
                //Value::Null => return,
                //Value::Bool(_) => todo!(),
                //Value::Number(_) => todo!(),
                Value::String(str) => {
                    if str.is_empty() {
                        return Ok("".to_string());
                    }
                }
                Value::Array(_array) => {
                    //println!("[build_field()] array = {:?}", array);
                    //todo!()
                    return Ok("".to_string());
                }
                Value::Object(_) => {
                    //string_buffer.push(value.to_string());
                    return Ok("".to_string());
                }
                _ => {}
            }

            value
        } else {
            return Ok("".to_string());
        };

        let properties = server_connection.login_response.openapi
            .get_properties_from_schema_name(parent_name, schema_name, &SchemaPlace::Schemas)
            .ok_or_else(|| format!("Missing properties in openapi schema {:?}.{}", parent_name, schema_name))?;
        let field = properties.get(field_name).ok_or_else(|| format!("Don't found field {} in properties", field_name))?;

        match &field {
            ReferenceOr::Reference { reference } => {
                return build_field_reference(server_connection, schema_name, field_name, obj, reference);
            }
            ReferenceOr::Item(field) => {
                let extensions = &field.schema_data.extensions;

                if let Some(reference) = extensions.get("x-$ref") {
                    if let Value::String(reference) = reference {
                        return build_field_reference(server_connection, schema_name, field_name, obj, &reference);
                    }
                }
            }
        }

        // TODO : verificar se o uso do "trim" não tem efeitos colaterais.
        let str = match value {
            Value::String(str) => str.trim().to_string(),
            Value::Null => "".to_string(),
            Value::Bool(value) => value.to_string(),
            Value::Number(value) => {
                if field_name == "id" && value.is_u64() {
                    format!("{:04}", value.as_u64().unwrap())
                } else {
                    value.to_string()
                }
            }
            Value::Array(_) => "".to_string(),
            Value::Object(_) => "".to_string(),
        };

        Ok(str)
    }

    fn build_item_str(&self, server_connection: &ServerConnection, item: &Value) -> Result<String, Box<dyn std::error::Error>> {
        let mut string_buffer = vec![];

        for field_name in &self.short_description_list {
            let str = Service::build_field_str(server_connection, &None, &self.schema_name, field_name, item)?;
            string_buffer.push(str); //trim
        }

        let str = string_buffer.join(" - ");
        Ok(str)
    }

}

#[derive(Serialize, Debug, Clone)]
struct HtmlElementState {
    hidden: bool,
    disabled: bool,
}

impl Default for HtmlElementState {
    fn default() -> Self {
        Self { hidden: true, disabled: false }
    }
}

#[derive(Serialize, Debug)]
pub struct DataViewResponse {
    html: Value,
    changes: Value,
    tables: Value,
    aggregates: Value,
    forms: HashMap<String, HtmlElementState>
}

impl Default for DataViewResponse {
    fn default() -> Self {
        Self { html: json!({}), changes:  json!({}), tables:  json!({}), aggregates:  json!({}), forms: HashMap::default() }
    }
}

#[derive(PartialEq, Default)]
pub enum DataViewType {
    #[default]
    Primary,
    ObjectProperty,
    Child(Dependent),
}

#[derive(Debug, Clone, Default)]
pub struct DataViewId {
    pub parent_action: Option<DataViewProcessAction>,
    pub action: DataViewProcessAction,
    pub parent_schema_name: Option<String>,
    pub schema_name: String,
    pub parent_id: Option<String>,
    pub id: String,
}

impl DataViewId {
    pub fn new(schema_name: String, parent: Option<DataViewId>, action: DataViewProcessAction) -> Self {
        let schema_name_snake = schema_name.to_case(convert_case::Case::Snake);//.replace(".", "/");

        let schema_name_snake = if schema_name_snake.starts_with("v_") {
            schema_name_snake.replace("v_", "v")
        } else {
            schema_name_snake
        };

        let (parent_schema_name, parent_action, parent_id, id) = if let Some(parent) = parent {
            let id = format!("{}--{}-{}", parent.id, action, schema_name_snake);
            let parent_schema_name = Some(parent.schema_name.clone());
            let parent_action = Some(parent.action.clone());
            (parent_schema_name, parent_action, Some(parent.id.clone()), id)
        } else {
            let id = format!("{}-{}", action, schema_name_snake);
            (None, None, None, id)
        };

        Self {parent_action, action, parent_schema_name, schema_name, parent_id, id}
    }
    
    fn set_action(&mut self, action: DataViewProcessAction) {
        self.action = action;
        let schema_name_snake = self.schema_name.to_case(convert_case::Case::Snake);

        if let Some(parent_id) = &self.parent_id {
            self.id = format!("{}--{}-{}", parent_id, action, schema_name_snake);
        } else {
            self.id = format!("{}-{}", action, schema_name_snake);
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct HtmlElementId {
    pub data_view_id: DataViewId,
    form_type_ext: Option<String>,
    field_name: Option<String>,
    index: Option<usize>,
}

impl HtmlElementId {   
    pub fn new_with_data_view_id(data_view_id: DataViewId, form_type_ext: Option<String>, field_name: Option<String>, index: Option<usize>) -> Self {
        Self {data_view_id, form_type_ext, field_name, index}
    }

    pub fn new(schema_name: String, parent: Option<DataViewId>, form_type_ext: Option<String>, action: DataViewProcessAction, field_name: Option<String>, index: Option<usize>) -> Self {
        let data_view_id = DataViewId::new(schema_name, parent, action);
        Self {data_view_id, form_type_ext, field_name, index}
    }

    fn new_with_regex(cap: &regex::Captures) -> Result<Self, Box<dyn std::error::Error>> {
        let schema_name_snake = cap.name("name").ok_or_else(|| format!("context name"))?.as_str().replace(".", "/");
        let schema_name = schema_name_snake.to_case(convert_case::Case::Camel);
        let action_str = cap.name("action").ok_or_else(|| format!("Missing action in HtmlElementId.new_with_regex"))?.as_str();
        let action = DataViewProcessAction::from(action_str);

        let parent = {
            if let Some(parent) = cap.name("parent_name") {
                let schema_name = parent.as_str().to_case(convert_case::Case::Camel);

                if let Some(action) = cap.name("parent_action") {
                    let action = DataViewProcessAction::from(action.as_str());
                    Some(DataViewId::new(schema_name, None, action))
                } else {
                    Some(DataViewId::new(schema_name, None, action))
                }
            } else {
                None
            }    
        };

        let data_view_id = DataViewId::new(schema_name, parent, action);

        let form_type_ext = match cap.name("form_type_ext") {
            Some(form_type_ext) => Some(form_type_ext.as_str().to_string()),
            None => None,
        };

        let field_name = match cap.name("field_name") {
            Some(field_name) => Some(field_name.as_str().to_string()),
            None => None,
        };

        let index = match cap.name("index") {
            Some(index) => Some(index.as_str().parse::<usize>()?),
            None => None,
        };

        Ok(Self {data_view_id, form_type_ext, field_name, index})
    }
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct DataViewParams {
    primary_key: Option<Value>,
    filter: Value,
    filter_range: Value,
    filter_range_min: Value,
    filter_range_max: Value,
    aggregate: Value,
    sort: IndexMap<String, FieldSort>,
    page: usize,
    page_size: usize,
    pub instance: Value,
    origin: Option<String>,
}

impl Default for DataViewParams {
    fn default() -> Self {
        Self { primary_key: Default::default(), filter: json!({}), filter_range: json!({}), filter_range_min: json!({}), filter_range_max: json!({}), aggregate: json!({}), sort: Default::default(), page: 0, page_size: 25, instance: json!({}), origin: Default::default() }
    }
}

#[derive(Default)]
pub struct DataView {
    pub params: DataViewParams,
    // const
    pub data_view_id: DataViewId,
    pub path: Option<String>,
    typ: DataViewType,
    state: HtmlElementState,
    is_one_to_one: bool,
    short_description_list: Vec<String>,
    extensions: SchemaExtensions,
    properties: SchemaProperties,
    fields_table: Vec<String>,
    pub childs: Vec<DataView>,
    // mutable
    properties_modified: IndexMap<String, Value>,
    // data
    original: Value,
    // data aux
    active_index: Option<usize>, // active index of filter_results
    instance_flags: HashMap<String, Vec<bool>>,
    // data list aggregate
    aggregate_results: HashMap<String, usize>,
    // list data
    pub filter_results: Vec<Value>,
    field_filter_results: IndexMap<String, Value>,
    pub field_results: IndexMap<String, Vec<Value>>,
    field_results_str: IndexMap<String, Vec<String>>,
    field_external_references_str: IndexMap<String, String>,
}

impl DataView {
    pub fn new(path_or_name: &str, typ: DataViewType, parent: Option<DataViewId>, action: DataViewProcessAction) -> Self {
        let (path, schema_name) = if path_or_name.starts_with("/") {
            (Some(path_or_name.to_string()), path_or_name[1..].to_string().to_case(convert_case::Case::Camel))
        } else {
            (None, path_or_name.to_string())
        };

        let state = match &parent {
            Some(parent_id) => {
                match &parent_id.action {
                    DataViewProcessAction::New => HtmlElementState::default(),
                    DataViewProcessAction::Edit => {
                        match &action {
                            DataViewProcessAction::New => HtmlElementState{hidden: true, disabled: false},
                            DataViewProcessAction::Edit => HtmlElementState{hidden: true, disabled: false},
                            DataViewProcessAction::View => HtmlElementState{hidden: true, disabled: false},
                            DataViewProcessAction::Search => HtmlElementState::default(),
                            DataViewProcessAction::Filter => HtmlElementState::default(),
                            DataViewProcessAction::Aggregate => HtmlElementState::default(),
                            DataViewProcessAction::Sort => HtmlElementState::default(),
                        }
                    },
                    DataViewProcessAction::View => HtmlElementState::default(),
                    DataViewProcessAction::Search => HtmlElementState::default(),
                    DataViewProcessAction::Filter => HtmlElementState::default(),
                    DataViewProcessAction::Aggregate => HtmlElementState::default(),
                    DataViewProcessAction::Sort => HtmlElementState::default(),
                }
            },
            None => {
                match &action {
                    DataViewProcessAction::New => HtmlElementState{hidden: false, disabled: false},
                    DataViewProcessAction::Edit => HtmlElementState{hidden: false, disabled: false},
                    DataViewProcessAction::View => HtmlElementState{hidden: false, disabled: false},
                    _ => HtmlElementState::default(),
                }
            },
        };

        let element_id = HtmlElementId::new(schema_name, parent, None, action, None, None);
        let data_view_id = element_id.data_view_id.clone();
        let mut params = DataViewParams::default();
        params.page = 1;
        println!("[DataView::new()] : {}", data_view_id.id);

        Self {
            params,
            data_view_id,
            path,
            typ,
            original: json!({}),
            state,
            ..Default::default()
        }
    }

    pub fn set_schema(&mut self, server_connection: &ServerConnection) -> Result<(), Box<dyn std::error::Error>> {
        let Some(path) = &self.path else {
            return Ok(());
        };

        let (methods, schema_place) = match self.data_view_id.action {
            DataViewProcessAction::New => (["post","put"], SchemaPlace::Request),
            DataViewProcessAction::Edit => (["put","post"], SchemaPlace::Request),
            _ => (["get","post"], SchemaPlace::Response),
        };

        let (short_description_list, _, properties, _method) = server_connection.login_response.openapi.get_properties_with_extensions(path, &methods, &schema_place)?;
        self.properties = properties;
        self.short_description_list = short_description_list;

        if let Some(property) = self.properties.get_mut("rufsGroupOwner") {
            match property {
                ReferenceOr::Item(property) => {
                    property.schema_data.extensions.insert("x-hidden".to_string(), Value::Bool(true));
                    property.schema_data.extensions.insert("x-tableVisible".to_string(), Value::Bool(false));
                    property.schema_data.default = Some(json!(server_connection.login_response.rufs_group_owner));
                }
                _ => todo!(),
            };
        }

        if let DataViewType::Child(dependent) = &self.typ {
            let field_name = &dependent.field;

            if let Some(property) = self.properties.get_mut(field_name) {
                match property {
                    ReferenceOr::Item(property) => {
                        property.schema_data.extensions.insert("x-hidden".to_string(), Value::Bool(true));
                        property.schema_data.extensions.insert("x-tableVisible".to_string(), Value::Bool(false));
                    }
                    _ => todo!(),
                };
            }
        }

        Ok(())
    }

    pub fn clear(&mut self, server_connection: &ServerConnection, watcher: &Box<dyn DataViewWatch>) -> Result<(), Box<dyn std::error::Error>> {
        self.set_values(server_connection, watcher, &json!({}), None)?;
        self.original.as_object_mut().ok_or_else(|| format!("broken original"))?.clear();
        self.params.instance.as_object_mut().ok_or_else(|| format!("broken params.instance"))?.clear();
        self.instance_flags.clear();
        self.field_external_references_str.clear();

        self.clear_filter()?;
        self.clear_sort()?;
        self.clear_aggregate()?;

        for data_view in &mut self.childs {
            data_view.clear(server_connection, watcher)?;
        }

        Ok(())
    }

    fn build_changes(&mut self, data_out: &mut Value) -> Result<(), Box<dyn std::error::Error>> {
        if self.properties_modified.len() > 0 {
            let mut form = json!({});

            for (field_name, value) in &self.properties_modified {
                form[field_name] = json!(value);
            }
    
            data_out[self.data_view_id.id.clone()] = form;
            self.properties_modified.clear();
        }

        for data_view in &mut self.childs {
            data_view.build_changes(data_out)?;
        }

        Ok(())
    }

    fn build_form(data_view: &DataView, action: DataViewProcessAction) -> Result<String, Box<dyn std::error::Error>> {
        let mut data_view_id = data_view.data_view_id.clone();
        data_view_id.set_action(action);
        let form_id = &data_view_id.id;
        let title = data_view.data_view_id.schema_name.to_case(convert_case::Case::Title);
        let table = format!(r#"<div id="div-table-{form_id}"></div>"#);

        if action == DataViewProcessAction::Search {
            let href_new = DataView::build_location_hash(&data_view.data_view_id, &DataViewProcessAction::New, &json!({}))?;
            let header = format!(r#"<div class="card-header"><a href="{href_new}" id="create-{form_id}" class="btn btn-default"><i class="bi bi-plus"></i> {title}</a></div>"#);

            let search = if data_view.data_view_id.parent_schema_name.is_none() {
                let html_filter = DataView::build_form(data_view, DataViewProcessAction::Filter)?;
                let html_aggregate = DataView::build_form(data_view, DataViewProcessAction::Aggregate)?;
                let html_sort = DataView::build_form(data_view, DataViewProcessAction::Sort)?;
                format!(r##"
                    <div class="panel panel-default" ng-if="vm.rufsService.list.length > 0 || vm.rufsService.access.get == true">
                        <nav>
                            <div class="nav nav-tabs" role="tablist" id="nav-tab-{form_id}">
                                <button class="nav-link" data-bs-toggle="tab" data-bs-target="#nav-filter-{form_id}"      role="tab" type="button" aria-controls="nav-filter-{form_id}"      aria-selected="false" id="nav-tab-filter-{form_id}">Filtro</button>
                                <button class="nav-link" data-bs-toggle="tab" data-bs-target="#nav-aggregate-{form_id}"   role="tab" type="button" aria-controls="nav-aggregate-{form_id}"   aria-selected="false" id="nav-tab-aggregate-{form_id}">Relatório</button>
                                <button class="nav-link" data-bs-toggle="tab" data-bs-target="#nav-sort-{form_id}"        role="tab" type="button" aria-controls="nav-sort-{form_id}"        aria-selected="false" id="nav-tab-sort-{form_id}">Ordenamento</button>
                            </div>
                        </nav>
                    
                        <div class="tab-content">
                            <div class="tab-pane fade" id="nav-filter-{form_id}" role="tabpanel" aria-labelledby="nav-tab-filter-{form_id}" tabindex="0">
                            {html_filter}
                            </div>
                        
                            <div class="tab-pane fade" id="nav-aggregate-{form_id}" role="tabpanel" aria-labelledby="nav-tab-aggregate-{form_id}" tabindex="0">
                            <canvas id="chart-aggregate-{form_id}"></canvas>
                            {html_aggregate}
                            </div>
                        
                            <div class="tab-pane fade" id="nav-sort-{form_id}" role="tabpanel" aria-labelledby="nav-tab-sort-{form_id}" tabindex="0">
                            {html_sort}
                            </div>
                        </div>
                    </div>
                "##)                    
            } else {
                String::new()
            };

            let str = format!(r##"
            <div id="div-{form_id}" class="card" hidden>
                {header}
                <div class="card-body">
                    {search}
                    {table}
                </div>
            </div>
            "##);

            return Ok(str);
        }

        let mut hmtl_fields = vec![];

        for (field_name, field) in &data_view.properties {
            let field = field.as_item().ok_or_else(|| format!("field is reference"))?;
            let extension = &field.schema_data.extensions;

            if let Some(hidden) = extension.get("x-hidden") {
                if hidden == &json!(true) {
                    continue;
                }
            }
/*
            if let DataViewType::Child(dependent) = &data_view.typ {
                // TODO : ocultar os campos foreginkeys do pai.
                if field_name == &dependent.field {
                    continue;
                }
            }
*/
            let typ = match &field.schema_kind {
                SchemaKind::Type(typ) => typ,
                SchemaKind::Any(_) => todo!(),
                _ => continue,
            };

            let (html_input_typ, html_input_step, html_input_pattern, html_input_max_length, col_size, is_rangeable) = if let Some(_reference) = extension.get("x-$ref") {
                ("text", "".to_string(), "", 1024, 8, false)
            } else {
                match typ {
                    Type::String(typ) => {
                        let max_length = typ.max_length.unwrap_or(1024);
    
                        let col_size = if max_length > 110 { 11 } else { (max_length / 7) + 1 };
    
                        let (html_input_typ, is_rangeable) = match &typ.format {
                            VariantOrUnknownOrEmpty::Item(format) => match format {
                                StringFormat::Date => ("date", true),
                                StringFormat::DateTime => ("datetime-local", true),
                                StringFormat::Password => ("text", false),
                                StringFormat::Byte => ("text", false),
                                StringFormat::Binary => ("text", false),
                            },
                            _ => ("text", false),
                        };
    
                        (html_input_typ, "".to_string(), "", max_length, col_size, is_rangeable)
                    }
                    Type::Number(_typ) => {
                        let precision: usize = extension.get("x-precision").unwrap_or(&json!(12)).as_u64().unwrap_or(12).try_into().unwrap_or(12);
                        let scale = if let Some(scale) = extension.get("x-scale") {
                            match scale.as_u64().unwrap_or(3) {
                                1 => "0.1",
                                3 => "0.001",
                                4 => "0.0001",
                                5 => "0.00001",
                                _ => "0.01",
                            }
                        } else {
                            "0.01"
                        };
    
                        ("number", format!(r#"step="{}""#, scale), "", precision, 2, true)
                    }
                    Type::Integer(_typ) => {
                        if let Some(_reference) = extension.get("x-$ref") {
                            ("text", "".to_string(), "", 1024, 8, false)
                        } else {
                            ("number", r#"step="1""#.to_string(), r#"pattern="\d+""#, 15, 2, true)
                        }
                    }
                    Type::Boolean {} => ("checkbox", "".to_string(), "", 0, 1, false),
                    Type::Object(_) => continue,
                    Type::Array(_) => continue,
                }
            };

            let mut html_options = vec![];

            let html_input = match typ {
                Type::Object(_) => {
                    format!(
                        r##"

                    "##
                    )
                }
                Type::Array(_) => {
                    format!(
                        r##"
                    
                    "##
                    )
                }
                _ => {
                    if data_view.data_view_id.action != DataViewProcessAction::View {
                        if let Some(list) = data_view.field_results_str.get(field_name) {
                            for str in list {
                                html_options.push(format!(r##"<option value="{str}">{str}</option>"##));
                            }
                        }
                    }

                    let html_options_str = html_options.join("\n");

                    if data_view.data_view_id.action != DataViewProcessAction::View && html_options.len() > 0 && html_options.len() <= 20 {
                        format!(
                            r##"
                        <select class="form-control" id="{form_id}--{field_name}" name="{field_name}" ng-required="field.essential == true && field.nullable != true" ng-disabled="{{field.readOnly == true}}">
                            <option value=""></option>
                            {html_options_str}
                        </select>
                        "##
                        )
                    } else {
                        // ng-disabled="{{field.readOnly == true}}"
                        let disabled = if data_view.data_view_id.action == DataViewProcessAction::View { "disabled" } else { "" };

                        format!(r##"
                        <input class="form-control" id="{form_id}--{field_name}" name="{field_name}" type="{html_input_typ}" {html_input_step} {html_input_pattern} maxlength="{html_input_max_length}" placeholder="" ng-required="field.essential == true && field.nullable != true" {disabled} list="list--{form_id}--{field_name}" autocomplete="off">
                        <datalist ng-if="field.filterResultsStr.length >  20" id="list--{form_id}--{field_name}">
                            {html_options_str}
                        </datalist>
                        "##)
                    }
                }
            };

            let (html_external_search, html_references) = if let Some(_reference) = extension.get("x-$ref") {
                //let reference = reference.as_str().ok_or_else(|| format!("not string content"))?;
                let mut list = vec![];
                list.push(format!(
                    r##"<div class="col-1"><a id="reference-view-{form_id}--{field_name}" name="reference-view-{field_name}" class="btn btn-secondary" href="#"><i class="bi bi-eye-fill"></i></a></div>"##
                ));

                let html_external_search = if data_view.data_view_id.action != DataViewProcessAction::View {
                    list.push(format!(r##"<div class="col-1"><a id="reference-create-{form_id}--{field_name}" name="reference-create-{field_name}" class="btn btn-secondary" href="#"><i class="bi bi-plus"></i></a></div>"##));
                    let html_external_search = format!(
                        r##"<div class="col-1"><a id="reference-search-{form_id}--{field_name}" name="reference-search-{field_name}" class="btn btn-secondary" href="#"><i class="bi bi-search"></i></a></div>"##
                    );
                    list.push(html_external_search.clone());
                    html_external_search
                } else {
                    "".to_string()
                };

                (html_external_search, list.join("\n"))
            } else {
                ("".to_string(), "".to_string())
            };

            let html_flags = if let Some(flags) = extension.get("x-flags") {
                let flags = flags.as_array().ok_or_else(|| format!("Not array content in extension 'x-flags' of field {}, content : {}", field_name, flags))?;
                let mut list = vec![];
                let mut index = 0;

                for label in flags {
                    let label = label.as_str().ok_or_else(|| format!("not string content"))?;

                    list.push(format!(
                        r##"
                    <div class="form-group form-group row">
                        <label class="col-offset-1 control-label">
                            <input type="checkbox" id="{form_id}--{field_name}-{index}" name="{field_name}-{index}"/>
                            {label}
                        </label>
                    </div>
                    "##
                    ));
                    index += 1;
                }

                list.join("\n")
            } else {
                "".to_string()
            };

            let label = field_name.to_case(convert_case::Case::Title);
            let str = match action {
                DataViewProcessAction::Filter => {
                    let html_field_range = if ["date", "datetime-local"].contains(&html_input_typ) {
                        let filter_range_options = [
                            " hora corrente ",
                            " hora anterior ",
                            " uma hora ",
                            " dia corrente ",
                            " dia anterior ",
                            " um dia ",
                            " semana corrente ",
                            " semana anterior ",
                            " uma semana ",
                            " quinzena corrente ",
                            " quinzena anterior ",
                            " uma quinzena ",
                            " mês corrente ",
                            " mês anterior ",
                            " um mês ",
                            " ano corrente ",
                            " ano anterior ",
                            " um ano ",
                        ];
                        let mut html_options = vec![];

                        for option in filter_range_options {
                            html_options.push(format!(r##"<option value="{option}">{option}</option>"##));
                        }

                        let html_options = html_options.join("\n");
                        format!(
                            r#"
                        <div class="form-group">
                            <div ng-if="field.htmlType.includes('date')" class="col-offset-3 col-9">
                                <select class="form-control" id="{form_id}--{field_name}-range" name="{field_name}-range" ng-model="vm.instanceFilterRange[fieldName]" ng-change="vm.setFilterRange(fieldName, vm.instanceFilterRange[fieldName])">
                                    <option value=""></option>
                                    {html_options}
                                </select>
                            </div>
                        </div>	    
                        "#
                        )
                    } else {
                        "".to_string()
                    };

                    let html_input = if html_options.len() > 0 {
                        format!(r#"<div class="col">{html_input}</div>"#)
                    } else {
                        match typ {
                            Type::Object(_) => "".to_string(),
                            Type::Array(_) => "".to_string(),
                            _ => {
                                if is_rangeable {
                                    format!(
                                        r#"
                                    <div class="col-4">
                                        <input class="form-control" id="{form_id}--{field_name}@min" name="{field_name}@min" type="{html_input_typ}" {html_input_step} placeholder="">
                                    </div>
                            
                                    <label for="{field_name}@max" class="col-1 control-label" style="text-align: center">à</label>
                            
                                    <div class="col-4">
                                        <input class="form-control" id="{form_id}--{field_name}@max" name="{field_name}@max" type="{html_input_typ}" {html_input_step} placeholder="">
                                    </div>
                                    "#
                                    )
                                } else {
                                    format!(
                                        r#"
                                    <div class="col-9">
                                        <input class="form-control" id="{form_id}--{field_name}" name="{field_name}" type="{html_input_typ}" {html_input_step} placeholder="">
                                    </div>
                                    "#
                                    )
                                }
                            }
                        }
                    };

                    format!(
                        r#"
                        {html_field_range}
                        <div id="div-filter-{form_id}--{field_name}" class="form-group row">
                            <label for="{form_id}--{field_name}" class="control-label col-2">{label}</label>
                            {html_input}
                            {html_external_search}
                        </div>
                    "#
                    )
                }
                DataViewProcessAction::Aggregate => {
                    let html_input = if ["date", "datetime-local"].contains(&html_input_typ) {
                        let mut html_options = vec![];

                        for aggregate_range_option in ["", "hora", "dia", "mês", "ano"] {
                            html_options.push(format!(r##"<option value="{aggregate_range_option}">{aggregate_range_option}</option>"##));
                        }

                        let html_options = html_options.join("\n");
                        format!(
                            r#"
                        <div id="div-col-9-{form_id}--{field_name}" class="col-9">
                            <select class="form-control" id="{form_id}--{field_name}" name="{field_name}">
                                <option value=""></option>
                                {html_options}
                            </select>
                        </div>
                        "#
                        )
                    } else {
                        let html_input = if is_rangeable {
                            format!(r#"<input  class="form-control" id="{form_id}--{field_name}" name="{field_name}" type="{html_input_typ}" {html_input_step} placeholder="">"#)
                        } else {
                            format!(r#"<input  class="form-control" id="{form_id}--{field_name}" name="{field_name}" type="checkbox">"#)
                        };

                        format!(r#"<div id="div-col-4-{form_id}--{field_name}" class="col-4">{html_input}</div>"#)
                    };

                    format!(r#"<div id="div-aggregate-{form_id}--{field_name}" class="form-group row"><label for="{form_id}--{field_name}" class="control-label">{label}</label>{html_input}</div>"#)
                }
                DataViewProcessAction::Sort => {
                    format!(
                        r#"
                        <div id="div-sort-{form_id}--{field_name}" class="form-group row">
                            <label for="{form_id}--{field_name}" class="control-label">{label}</label>
                                
                            <div id="div-{form_id}--{field_name}-order_by" class="col-3">
                                <select class="form-control" id="{form_id}--{field_name}-order_by" name="{field_name}-order_by" ng-model="vm.properties[fieldName].sortType">
                                    <option value="asc">asc</option>
                                    <option value="desc">desc</option>
                                </select>
                            </div>
                    
                            <div id="div-{form_id}--{field_name}-index" class="col-3">
                                <input  class="form-control" id="{form_id}--{field_name}-index" name="{field_name}-index" ng-model="vm.properties[fieldName].orderIndex" type="number" step="1">
                            </div>
                    
                            <div id="div-{form_id}--{field_name}-table_visible" class="col-3">
                                <input  class="form-control" id="{form_id}--{field_name}-table_visible" name="{field_name}-table_visible" type="checkbox">
                            </div>
                        </div>
                    "#
                    )
                }
                _ => {
                    format!(
                        r##"
                        <div id="div-col-size-{form_id}--{field_name}" class="col-{col_size}">
                            <label for="{form_id}--{field_name}" class="control-label">{label}</label>
                            <div id="div-row-{form_id}--{field_name}" class="row">
                                <div id="div-col-{form_id}--{field_name}" class="col">{html_input}</div>
                                {html_references}
                                {html_flags}
                            </div>
                        </div>
                        "##
                    )
                }
            };

            hmtl_fields.push(str);
        }

        let html_fields = hmtl_fields.join("\n");
        let mut crud_item_json = vec![];

        let (form_class, hidden_form) = match action {
            DataViewProcessAction::New | DataViewProcessAction::Edit | DataViewProcessAction::View => {
                for data_view in &data_view.childs {
                    let html = DataView::build_form(data_view, data_view.data_view_id.action)?;
                    crud_item_json.push(html);
                }

                ("row", "hidden")
            }
            _ => ("form-horizontal", ""),
        };

        let html_crud_items = crud_item_json.join("\n");

        let hidden = if data_view.data_view_id.parent_schema_name.is_none() {
            ""
        } else {
            "hidden"
        };

        let mut form_actions = vec![];

        if data_view.data_view_id.action != DataViewProcessAction::View {
            form_actions.push(format!(r#"<button id="apply-{form_id}"  name="apply"  class="btn btn-primary"><i class="bi bi-apply"></i> Aplicar</button>"#));
            form_actions.push(format!(r#"<button id="clear-{form_id}"  name="clear"  class="btn btn-default"><i class="bi bi-erase"></i> Limpar</button>"#));
        }

        if data_view.data_view_id.action == DataViewProcessAction::Edit {
            form_actions.push(format!(r#"<button id="delete-{form_id}" name="delete" class="btn btn-default"><i class="bi bi-remove"></i> Remove</button>"#));
        }

        let form_actions = form_actions.join("\n");

        let str = format!(r##"
            <div id="div-{form_id}" class="card" {hidden}>
                <div id="div-card-header-{form_id}" class="card-header">{title}</div>
                <div id="div-card-body-{form_id}" class="card-body">
                    <form id="{form_id}" name="{form_id}" role="form" {hidden_form}>
                        <fieldset id="fieldset-{form_id}" name="fieldset-{form_id}" class="{form_class}"> 
                            {html_fields}
                            <div id="div-actions-{form_id}" class="form-group">
                                {form_actions}
                                <button id="cancel-{form_id}" name="cancel" class="btn btn-default"><i class="bi bi-exit"></i> Fechar</button>
                            </div>
                        </fieldset> 
                    </form>
                    {html_crud_items}
                    {table}
                </div>
            </div>
        "##);

        Ok(str)
    }

    fn build_table(server_connection: &ServerConnection, data_view: &mut DataView, params_search: &DataViewParams) -> Result<String, Box<dyn std::error::Error>> {
        fn build_href(server_connection: &ServerConnection, data_view: &DataView, item: &Value, action: &DataViewProcessAction) -> Result<String, Box<dyn std::error::Error>> {
            let str = if data_view.path.is_some() {
                let service = server_connection.service_map.get(&data_view.data_view_id.schema_name).ok_or_else(|| format!("Missing service"))?;
                let primary_key = &service.get_primary_key(item).ok_or_else(|| {
                    format!("[DataView.build_table] {} : Missing primary key", service.path)                    
                })?;
                DataView::build_location_hash(&data_view.data_view_id, action, primary_key)?
            } else {
                "".to_string()
            };

            Ok(str)
        }

        if data_view.fields_table.is_empty() {
            data_view.clear_sort()?;
        }

        let form_id = &data_view.data_view_id.id;

        let list = if data_view.path.is_none() || data_view.filter_results.len() > 0 {
            &data_view.filter_results
        } else {
            let schema_name = &data_view.data_view_id.schema_name;
            let service = server_connection.service_map.get(schema_name).ok_or_else(|| format!("3 - service_map : missing {}.", schema_name))?;
            &service.list
        };

        if list.len() == 0 {
            return Ok("".to_string());
        }

        let mut hmtl_header = vec![];

        for field_name in &data_view.fields_table {
            let label = field_name.to_case(convert_case::Case::Title);
            let col = format!(
                r##"
            <th>
                <a href="#" id="sort_left-{form_id}--{field_name}"><i class="bi bi-arrow-left"></i> </a>
                <a href="#" id="sort_toggle-{form_id}--{field_name}"> {label}</a>
                <a href="#" id="sort_rigth-{form_id}--{field_name}"><i class="bi bi-arrow-right"></i> </a>
            </th>
            "##
            );
            hmtl_header.push(col);
        }

        let mut offset_ini = (data_view.params.page - 1) * data_view.params.page_size;

        if offset_ini > list.len() {
            offset_ini = list.len();
        }

        let mut offset_end = data_view.params.page * data_view.params.page_size;

        if offset_end > list.len() {
            offset_end = list.len();
        }

        let mut hmtl_rows = vec![];
        let mut item_index = 0;

        for index in offset_ini..offset_end {
            let item = list.get(index).ok_or_else(|| format!("Broken: missing item at index"))?;

            if let Some(obj) = item.as_object() {
                if obj.is_empty() {
                    continue;
                }
            }
            
            let mut html_cols = vec![];

            for field_name in &data_view.fields_table {
                let href_go_to_field = if data_view.path.is_some() {
                    let element_id = HtmlElementId {data_view_id: data_view.data_view_id.clone(), field_name: Some(field_name.clone()), ..Default::default()};
                    data_view.build_go_to_field(server_connection, &element_id, &DataViewProcessAction::View, item)?.unwrap_or("#".to_string())
                } else {
                    "#".to_string()
                };

                let parent_name = &data_view.data_view_id.parent_schema_name;
                
                let field_str = if data_view.path.is_some() {
                    Service::build_field_str(server_connection, &None, &data_view.data_view_id.schema_name, field_name, item)?
                } else {
                    Service::build_field_str(server_connection, parent_name, &data_view.data_view_id.schema_name, field_name, item)?
                };

                html_cols.push(format!(r#"<td><a id="table_row-col-{form_id}--{field_name}-{index}" href="{href_go_to_field}">{field_str}</a></td>"#));
            }

            let html_cols = html_cols.join("\n");
            let mut html_row_actions = vec![];
            let href_view = build_href(server_connection, data_view, item, &DataViewProcessAction::View)?;
            html_row_actions.push(format!(r##"<a id="table_row-view-{form_id}--{index}" href="{href_view}"><i class="bi bi-eye-fill"></i> View</a>"##));

            if data_view.data_view_id.parent_schema_name.is_none() || data_view.data_view_id.action != DataViewProcessAction::View {
                if let Some(_origin) = &params_search.origin {
                    html_row_actions.insert(0, format!(r##"<a id="search_select-new-{form_id}--{item_index}" href="#"><i class="bi bi-check-lg"></i> Select</a>"##));
                }

                let enable_edit = if let Some(action) = &data_view.data_view_id.parent_action {
                    action == &DataViewProcessAction::Edit
                } else {
                    true
                };

                if enable_edit {
                    let href_edit = build_href(server_connection, data_view, item, &DataViewProcessAction::Edit)?;
                    html_row_actions.push(format!(r##"<a id="table_row-edit-{form_id}--{index}"   href="{href_edit}"><i class="bi bi-eye-fill"></i> Edit</a>"##));
                    html_row_actions.push(format!(r##"<a id="table_row-remove-{form_id}--{index}" href="#"><i class="bi bi-trash"></i> Delete</a>"##));
                    html_row_actions.push(format!(r##"<a id="table_row-up-{form_id}--{index}"     href="#"><i class="bi bi-arrow-up"></i> Up</a>"##));
                    html_row_actions.push(format!(r##"<a id="table_row-down-{form_id}--{index}"   href="#"><i class="bi bi-arrow-down"></i> Down</a>"##));
                }
            }

            let html_row_actions = html_row_actions.join("\n");
            let row = format!(r##"
            <tr>
                <td>
                    {html_row_actions}
                </td>
                {html_cols}
            </tr>
            "##);
            hmtl_rows.push(row);
            item_index += 1;
        }

        let html_page_control = if list.len() > data_view.params.page_size {
            let max_page = if list.len() % data_view.params.page_size == 0 {
                list.len() / data_view.params.page_size
            } else {
                (list.len() / data_view.params.page_size) + 1
            };

            let mut html_pages = vec![];

            for page in 1..max_page {
                html_pages.push(format!(r##"<li class="page-item"><a class="page-link" id="selected_page-{form_id}--{page}" href="#">{page}</a></li>"##));
            }

            let html_pages = html_pages.join("\n");
            let page_size = data_view.params.page_size;
            format!(r##"
            <nav aria-label="Page navigation">
                <ul class="pagination">
                    <li class="page-item">
                        <a class="page-link" href="#" aria-label="Previous">
                            <span aria-hidden="true">&laquo;</span>
                        </a>
                    </li>
                    {html_pages}
                    <li class="page-item">
                        <a class="page-link" href="#" aria-label="Next">
                            <span aria-hidden="true">&raquo;</span>
                        </a>
                    </li>
                </ul>
            </nav>

            <div id="page_size-{form_id}" class="form-group row" ng-if="vm.filterResults.length > vm.pageSize">
                <label for="page-size" class="col-2 col-form-label">Page size</label>

                <div id="div-page_size-2-{form_id}" class="col-2">
                    <input class="form-control" id="page_size-{form_id}" name="page_size" type="number" step="1" value="{page_size}">
                </div>
            </div>
            "##)
        } else {
            "".to_string()
        };

        let html_header = hmtl_header.join("\n");
        let html_rows = hmtl_rows.join("\n");
        let ret = format!(
            r##"
            <table id="table-{form_id}" class="table table-responsive table-bordered table-striped clearfix" style="white-space: nowrap;">
                <thead>
                    <tr>
                        <th></th>
                        {html_header}
                    </tr>
                </thead>
                <tbody>
                {html_rows}
                </tbody>
            </table>
            {html_page_control}
        "##
        );
        Ok(ret)
    }

    fn clear_aggregate(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        self.params.aggregate.as_object_mut().ok_or_else(|| format!("broken obj"))?.clear();
        self.aggregate_results.clear();
        Ok(())
    }

    fn apply_aggregate(&mut self, server_connection: &ServerConnection, aggregate: &Value) -> Result<(), Box<dyn std::error::Error>> {
        fn label_from_date(date: DateTime<Local>, range: &str) -> String {
            let date_ranges = ["secound", "minute", "hora", "dia", "mês", "ano"];
            let typ = date_ranges.into_iter().position(|item| item == range).unwrap_or(0);
            let mut list = vec![];

            if typ <= 5 {
                list.push(format!("{} ", date.year()));
            }

            if typ <= 4 {
                list.push(format!("{}/", date.month()));
            }

            if typ <= 3 {
                list.push(format!("{}/", date.day()));
            }

            if typ <= 2 {
                list.push(format!("{} ", date.hour()));
            }

            list.join("")
        }

        if !aggregate.as_object().ok_or_else(|| format!("broken ok"))?.is_empty() {
            self.params.aggregate = aggregate.clone();
        }

        self.aggregate_results = HashMap::default();

        let list = if self.path.is_none() || self.filter_results.len() > 0 {
            &self.filter_results
        } else {
            let service = server_connection.service_map.get(&self.data_view_id.schema_name).ok_or_else(|| format!("Missing service in service_map"))?;
            &service.list
        };

        for item in list {
            let mut list_label = vec![];

            for (field_name, range) in self.params.aggregate.as_object().ok_or_else(|| format!("broken ok"))? {
                let Some(value) = item.get(field_name) else {
                    continue;
                };

                let Some(field) = self.properties.get(field_name) else {
                    continue;
                };

                let Some(field) = field.as_item() else {
                    continue;
                };

                let extension = &field.schema_data.extensions;

                let str = if let Some(_ref) = extension.get("x-$ref") {
                    let service = server_connection.service_map.get(&self.data_view_id.schema_name).ok_or_else(|| format!("[set_value_process] Missing service"))?;
                    Service::build_field_str(server_connection, &None, &service.schema_name, field_name, item)?
                } else {
                    match &field.schema_kind {
                        SchemaKind::Type(typ) => match typ {
                            Type::String(typ) => match &typ.format {
                                VariantOrUnknownOrEmpty::Item(typ) => match typ {
                                    StringFormat::Date => {
                                        let from: NaiveDateTime = value.as_str().unwrap_or("2023-01-01").parse()?;
                                        let date = Local.from_local_datetime(&from).unwrap();
                                        label_from_date(date, range.as_str().unwrap_or_default())
                                    }
                                    StringFormat::DateTime => todo!(),
                                    StringFormat::Password => todo!(),
                                    StringFormat::Byte => todo!(),
                                    StringFormat::Binary => todo!(),
                                },
                                VariantOrUnknownOrEmpty::Unknown(_) => todo!(),
                                VariantOrUnknownOrEmpty::Empty => todo!(),
                            },
                            Type::Number(_typ) => {
                                if let Some(range) = range.as_f64() {
                                    if range != 0.0 {
                                        let val: f64 = value.as_f64().unwrap_or(0.0) / range;
                                        let val = val.trunc() * range;
                                        format!("{}", val)
                                    } else {
                                        "".to_string()
                                    }
                                } else {
                                    "".to_string()
                                }
                            }
                            Type::Integer(_typ) => {
                                if let Some(_flags) = extension.get("x-flags") {
                                    format!("{:x}", value.as_u64().unwrap_or(0))
                                } else {
                                    if let Some(range) = range.as_u64() {
                                        if range != 0 {
                                            let val: u64 = value.as_u64().unwrap_or(0) / range;
                                            let val = val * range;
                                            format!("{}", val)
                                        } else {
                                            "".to_string()
                                        }
                                    } else {
                                        "".to_string()
                                    }
                                }
                            }
                            Type::Object(_) => todo!(),
                            Type::Array(_) => todo!(),
                            Type::Boolean {} => todo!(),
                        },
                        _ => todo!(),
                    }
                };

                list_label.push(str);
            }

            if list_label.len() > 0 {
                let label = list_label.join(",");
                let default: usize = 0;
                let last_count = self.aggregate_results.get(&label).unwrap_or(&default);
                self.aggregate_results.insert(label, last_count + 1);
            }
        }

        Ok(())
    }

    fn clear_filter(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        // hora corrente, hora anterior, uma hora, hoje, ontem, um dia, semana corrente, semana anterior, uma semana, quinzena corrente, quinzena anterior, 15 dias, mês corrente, mês anterior, 30 dias, ano corrente, ano anterior, 365 dias
        self.params.filter.as_object_mut().ok_or_else(|| format!("broken ok"))?.clear();
        self.params.filter_range.as_object_mut().ok_or_else(|| format!("broken ok"))?.clear();
        self.params.filter_range_min.as_object_mut().ok_or_else(|| format!("broken ok"))?.clear();
        self.params.filter_range_max.as_object_mut().ok_or_else(|| format!("broken ok"))?.clear();
        //self.clear()?;
        Ok(())
    }

    fn apply_filter(&mut self, list: &Vec<Value>) {
        fn match_object(expected_fields: &Value, actual_object: &Value, match_string_partial: bool, recursive: bool, compare_type: i8) -> Result<bool, Box<dyn std::error::Error>> {
            for (key, expected_property) in expected_fields.as_object().ok_or_else(|| format!("broken"))? {
                let Some(actual_property) = actual_object.get(key) else {
                    return Ok(false);
                };

                if !expected_property.is_null() && actual_property.is_null() {
                    return Ok(false);
                };

                let flag = match expected_property {
                    Value::Null => {
                        if !actual_property.is_null() {
                            return Ok(false);
                        }

                        true
                    }
                    Value::Bool(_) => expected_property == actual_property,
                    Value::Number(a) => {
                        if let Some(b) = actual_property.as_number() {
                            if compare_type > 0 {
                                a.as_f64().unwrap() >= b.as_f64().unwrap()
                            } else if compare_type < 0 {
                                a.as_f64().unwrap() <= b.as_f64().unwrap()
                            } else {
                                a == b
                            }
                        } else {
                            return Ok(false);
                        }
                    }
                    Value::String(expected_property_str) => {
                        if let Some(actual_property_str) = actual_property.as_str() {
                            if expected_property_str.len() == 14 && expected_property_str.as_str()[4..4] == "-"[0..0] && actual_property_str.len() == 14 && actual_property_str[4..4] == "-"[0..0] {
                                let cmp = expected_property_str.as_str().cmp(actual_property_str);

                                if compare_type > 0 && !cmp.is_ge() {
                                    return Ok(false);
                                } else if compare_type < 0 && !cmp.is_le() {
                                    return Ok(false);
                                } else {
                                    expected_property_str == actual_property_str
                                }
                            } else if match_string_partial {
                                if expected_property_str.len() > 0 {
                                    actual_property_str.trim_end().contains(expected_property_str.trim_end())
                                } else {
                                    true
                                }
                            } else {
                                actual_property_str.trim_end() == expected_property_str.trim_end()
                            }
                        } else {
                            return Ok(false);
                        }
                    }
                    Value::Array(_) => todo!(),
                    Value::Object(_obj) => {
                        if recursive == true {
                            if match_object(expected_property, actual_property, match_string_partial, recursive, compare_type)? == false {
                                return Ok(false);
                            }

                            true
                        } else {
                            expected_property == actual_property
                        }
                    }
                };

                if flag == false {
                    return Ok(false);
                }
            }

            Ok(true)
        }
        /*
                fn process_foreign(field_filter :&Value, obj :&Value, field_name :&str, compare_type :i8) -> Result<bool, Box<dyn std::error::Error>> {
                    fn compare_func(candidate :&Value, expected :&Value, compare_type :i8) -> Result<bool, Box<dyn std::error::Error>> {
                        match_object(expected, candidate, false, false, |a,b,field_name| {
                            if compare_type == 0 {
                                a == b
                            } else if compare_type < 0 {
                                a < b
                            } else {
                                a > b
                            }
                        })
                    }

                    let item = self.data_store_manager.get_primary_key_foreign(self.rufs_service, field_name, obj);
                    let service = self.data_store_manager.get_schema(item.schema);
                    let primary_key = item.primary_key;
                    let candidate = service.find_one(primary_key);
                    let mut flag = compare_func(candidate, field_filter.filter, 0)?;

                    if flag == true {
                        flag = compare_func(candidate, field_filter.filter_range_min, -1)?;

                        if flag == true {
                            flag = compare_func(candidate, field_filter.filter_range_max, 1)?;
                        }
                    }

                    Ok(flag)
                }
        */

        fn compare_func(candidate: &Value, expected: &Value, compare_type: i8) -> bool {
            if let Ok(ret) = match_object(expected, candidate, true, true, compare_type) {
                ret
            } else {
                false
            }
        }

        self.filter_results = list
            .into_iter()
            .filter(|candidate| {
                if candidate.is_object() {
                    let mut flag = compare_func(candidate, &self.params.filter, 0);

                    if flag == true {
                        flag = compare_func(candidate, &self.params.filter_range_min, -1);
    
                        if flag == true {
                            flag = compare_func(candidate, &self.params.filter_range_max, 1);
                        }
                    }
    
                    flag
                } else {
                    false
                }
            })
            .cloned()
            .collect();
    }

    fn apply_sort(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        if self.params.sort.is_empty() {
            return Ok(())
        }
        // format fieldsTable in correct order;
        {
            let mut entries: Vec<(&String, &FieldSort)> = self.params.sort.iter().collect();
            entries.sort_by(|a, b| a.1.order_index.cmp(&b.1.order_index));
            self.fields_table = vec![];

            for (field_name, field) in entries {
                if field.hidden != true && field.table_visible != false {
                    self.fields_table.push(field_name.clone());
                }
            }
        }

        self.filter_results.sort_by(|a, b| {
            let mut ret = Ordering::Equal;

            for field_name in &self.fields_table {
                let field = self.params.sort.get(field_name).unwrap();

                if field.sort_type != FieldSortType::None {
                    let val_a = a.get(field_name);
                    let val_b = b.get(field_name);

                    if val_a != val_b {
                        ret = if val_b.is_none() {
                            Ordering::Less
                        } else if val_a.is_none() {
                            Ordering::Greater
                        } else {
                            format!("{:0>9}", val_b.unwrap().to_string()).cmp(&format!("{:0>8}", val_a.unwrap().to_string()))
                        };

                        if field.sort_type == FieldSortType::Desc {
                            ret = ret.reverse()
                        }

                        if ret != Ordering::Equal {
                            break;
                        }
                    }
                }
            }

            ret
        });

        Ok(())
    }

    fn clear_sort(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        self.params.sort.clear();
        //let properties = self.schemaResponse != undefined ? self.schemaResponse.properties : self.properties;

        for (field_name, field) in &self.properties {
            if let DataViewType::Child(dependent) = &self.typ {
                // TODO : ocultar os campos foreginkeys do pai.
                if field_name == &dependent.field {
                    continue;
                }
            }
            
            if let ReferenceOr::Item(schema) = field {
                let extension = &schema.schema_data.extensions;
                let table_visible = extension.get("x-tableVisible").unwrap_or(&Value::Bool(false)).as_bool().unwrap_or(false);
                let hidden = extension.get("x-hidden").unwrap_or(&Value::Bool(false)).as_bool().unwrap_or(false);
                let order_index = extension.get("x-orderIndex").unwrap_or(&Value::from(0)).as_i64().unwrap_or(0);
                self.params.sort.insert(
                    field_name.clone(),
                    FieldSort {
                        sort_type: FieldSortType::None,
                        order_index,
                        table_visible,
                        hidden,
                    },
                );
            }
        }

        self.apply_sort()
    }

    fn get_form_type_instance(&self, action: &DataViewProcessAction, form_type_ext: &Option<String>) -> Result<&Value, Box<dyn std::error::Error>> {
        let instance = match action {
            DataViewProcessAction::New | DataViewProcessAction::Edit | DataViewProcessAction::View => &self.params.instance,
            DataViewProcessAction::Filter | DataViewProcessAction::Search => match form_type_ext {
                Some(form_type_ext) => {
                    if form_type_ext == "@max" {
                        &self.params.filter_range_max
                    } else {
                        &self.params.filter_range_min
                    }
                }
                None => &self.params.filter,
            },
            DataViewProcessAction::Aggregate => &self.params.aggregate,
            DataViewProcessAction::Sort => {
                todo!()
            },
        };

        Ok(instance)
    }

    pub fn set_value(&mut self, server_connection: &ServerConnection, watcher: &dyn DataViewWatch, field_name: &str, value: &Value, element_id: Option<&HtmlElementId>) -> Result<(), Box<dyn std::error::Error>> {
        fn get_value_old_or_default_or_null(field: &Schema, value_old: &Value) -> Value {
            let value_default = if let Some(default) = &field.schema_data.default {
                match &field.schema_kind {
                    SchemaKind::Type(typ) => match typ {
                        Type::String(typ) => match &typ.format {
                            VariantOrUnknownOrEmpty::Item(item) => match item {
                                StringFormat::Date => json!(Utc::now().to_rfc3339()),
                                StringFormat::DateTime => json!(Utc::now().to_rfc3339()),
                                _ => default.clone(),
                            },
                            _ => default.clone(),
                        },
                        _ => default.clone(),
                    },
                    _ => todo!(),
                }
            } else {
                Value::Null
            };

            if value_default.is_null() == false && value_old.is_null() == false {
                value_old.clone()
            } else {
                value_default
            }
        }

        fn u64_to_flags(value_in: u64) -> Vec<bool> {
            let mut flags = vec![];

            for k in 0..64 {
                let bit = 1 << k;
                let value = value_in & bit;
                flags.push(value != 0);
            }

            flags
        }

        fn set_form_type_value(data_view: &mut DataView, action: &DataViewProcessAction, form_type_ext: &Option<String>, field_name: &str, value: Value) -> Result<(), Box<dyn std::error::Error>> {
            match action {
                DataViewProcessAction::Filter => match form_type_ext {
                    Some(form_type_ext) => {
                        if form_type_ext == "@max" {
                            data_view.params.filter_range_max[field_name] = value
                        } else {
                            data_view.params.filter_range_min[field_name] = value
                        }
                    }
                    None => data_view.params.filter[field_name] = value,
                },
                DataViewProcessAction::Aggregate => data_view.params.aggregate[field_name] = value,
                DataViewProcessAction::Sort => todo!(),
                _ => {
                    data_view.params.instance[field_name] = value;

                    if data_view.typ == DataViewType::ObjectProperty {
                        if let Some(index) = data_view.active_index {
                            data_view.filter_results[index] = data_view.params.instance.clone();
                        }
                    }
                },
            }
    
            Ok(())
        }
    
        fn set_value_process(data_view: &mut DataView, server_connection: &ServerConnection, field_name: &str, value: &Value, element_id: &HtmlElementId, force_enable_null: bool) -> Result<(Value, Value, Value), Box<dyn std::error::Error>> {
            let value_old = data_view.get_form_type_instance(&element_id.data_view_id.action, &element_id.form_type_ext)?.get(field_name).unwrap_or(&Value::Null).clone();

            let field = data_view.properties.get(field_name).ok_or_else(|| {
                format!("set_value_process : missing field {} in data_view {}", field_name, data_view.data_view_id.id)
            })?;

            let field = match field {
                ReferenceOr::Reference { reference: _ } => todo!(),
                ReferenceOr::Item(schema) => schema.as_ref(),
            };

            let value = if value.is_null() {
                let value = get_value_old_or_default_or_null(field, &value_old);

                if value.is_null() && force_enable_null == false {
                    let force_enable_null = if data_view.data_view_id.action == DataViewProcessAction::Edit { false } else { true };

                    if force_enable_null || field.schema_data.nullable {
                        value
                    } else {
                        return None.ok_or_else(|| {
                            let str = format!("Received value null in {}.{}, force_enable_null = {}, field.schema_data.nullable = {}",
                                data_view.data_view_id.id, field_name, force_enable_null, field.schema_data.nullable
                            );
                            str
                        })?;
                    }
                } else {
                    value
                }
            } else {
                value.clone()
            };

            let extensions = &field.schema_data.extensions;

            if extensions.contains_key("x-$ref") {
                if value.is_null() {
                    data_view.field_external_references_str.insert(field_name.to_string(), "".to_string());
                } else {
                    let service = server_connection.service_map.get(&data_view.data_view_id.schema_name).ok_or_else(|| format!("[set_value_process] Missing service"))?;
                    let mut obj = data_view.get_form_type_instance(&element_id.data_view_id.action, &element_id.form_type_ext)?.clone();
                    obj[field_name] = value.clone();
                    let external_references_str = Service::build_field_str(server_connection, &None, &service.schema_name, field_name, &obj)?;
                    data_view.field_external_references_str.insert(field_name.to_string(), external_references_str.clone());
                }
            } else if extensions.contains_key("x-flags") && value.is_u64() {
                // field.flags : String[], vm.instanceFlags[fieldName] : Boolean[]
                data_view.instance_flags.insert(field_name.to_string(), u64_to_flags(value.as_u64().unwrap_or(0)));
            } else if extensions.contains_key("x-enum") {
                let empty_list = &Vec::<String>::new();
                let field_results_str = data_view.field_results_str.get(field_name).unwrap_or(empty_list);

                if value.is_object() {
                    let str_value = value.to_string();

                    if let Some(pos) = field_results_str.iter().position(|s| s == &str_value) {
                        //extensions.insert("x-externalReferencesStr".to_string(), json!(field_results_str[pos].clone()));
                        data_view.field_external_references_str.insert(field_name.to_string(), field_results_str[pos].clone());
                    } else {
                        //console.error(`${self.constructor.name}.setValue(${fieldName}) : don\'t found\nvalue:`, value, `\nstr:\n`, field.externalReferences, `\noptions:\n`, field.filterResultsStr);
                    }
                } else if value.is_null() {
                    data_view.field_external_references_str.insert(field_name.to_string(), "".to_string());
                } else {
                    if let Some(pos) = data_view.filter_results.iter().position(|v| v == &value) {
                        //extensions.insert("x-externalReferencesStr".to_string(), json!(field_results_str[pos].clone()));
                        data_view.field_external_references_str.insert(field_name.to_string(), field_results_str[pos].clone());
                    } else {
                        //console.error(`${self.constructor.name}.setValue(${fieldName}) : don\'t found\nvalue:`, value, `\nstr:\n`, field.externalReferences, `\noptions:\n`, field.filterResultsStr);
                    }
                }
            }

            let hidden = extensions.contains_key("x-hidden");

            let value = if !value.is_null() {
                //server_connection.login_response.openapi.copy_value(&data_view.path, &data_view.method, &data_view.schema_place, false /*true*/, field_name, &value)?//value || {}
                server_connection.login_response.openapi.copy_value_field(field, true, &value)?
            } else {
                value
            };

            let value_view = if hidden {
                Value::Null
            } else if let Some(value) = data_view.field_external_references_str.get(field_name) {
                json!(value)
            } else {
                value.clone()
            };

            Ok((value_old.clone(), value, value_view))
        }

        let (element_id, force_enable_null) = if let Some(element_id) = element_id {
            //HtmlElementId::new_with_data_view_id(self.data_view_id.clone(), element_id.form_type_ext.clone(), element_id.field_name.clone(), element_id.index)
            (element_id.clone(), false)
        } else {
            (HtmlElementId::new_with_data_view_id(self.data_view_id.clone(), None, None, None), true)
        };

        let (value_old, field_value, field_value_str) = if self.data_view_id.id != element_id.data_view_id.id {
            let data_view = self.childs.iter_mut().find(|data_view| data_view.data_view_id.id == element_id.data_view_id.id).ok_or_else(|| {
                format!("Missing item 5 {} in {}", element_id.data_view_id.id, self.data_view_id.id)
            })?;

            set_value_process(data_view, server_connection, field_name, value, &element_id, force_enable_null)?
        } else {
            set_value_process(self, server_connection, field_name, value, &element_id, force_enable_null)?
        };

        let changed_value = value_old != field_value;

        if changed_value && watcher.check_set_value(self, &element_id, server_connection, field_name, &field_value)? == true {
            fn set_value_show(data_view: &mut DataView, field_name: &str, field_value_str: Value, element_id: &HtmlElementId) -> Result<(), Box<dyn std::error::Error>> {
                let field = data_view.properties.get(field_name).ok_or_else(|| format!("Missing field {} in data_view {}", field_name, data_view.data_view_id.schema_name))?;
                let schema = field.as_item().ok_or_else(|| format!("field {} in data_view {} is reference", field_name, data_view.data_view_id.schema_name))?;
    
                if let Some(hidden) =  schema.schema_data.extensions.get("x-hidden") {
                    if hidden == &json!(true) {
                        return Ok(());
                    }
                }
    
                let field_name = if let Some(form_type_ext) = &element_id.form_type_ext {
                    [field_name, form_type_ext].join("")
                } else {
                    field_name.to_string()
                };

                data_view.properties_modified.insert(field_name, field_value_str);
                Ok(())
            }

            if self.data_view_id.id != element_id.data_view_id.id {
                let data_view = self.childs.iter_mut().find(|data_view| data_view.data_view_id.id == element_id.data_view_id.id).ok_or_else(|| {
                    format!("Missing item 4 {} in {}", element_id.data_view_id.id, self.data_view_id.id)
                })?;

                set_form_type_value(data_view, &element_id.data_view_id.action, &element_id.form_type_ext.clone(), field_name, field_value.clone())?;

                match &field_value {
                    Value::Array(array) => {
                        data_view.filter_results = array.clone();
                    }
                    Value::Object(_obj) => {}
                    _ => set_value_show(data_view, field_name, field_value_str, &element_id)?,
                }
            } else {
                set_form_type_value(self, &element_id.data_view_id.action, &element_id.form_type_ext.clone(), field_name, field_value.clone())?;

                match &field_value {
                    Value::Array(array) => {
                        let data_view = self.childs.iter_mut().find(|data_view| &data_view.data_view_id.schema_name == field_name && data_view.data_view_id.action == self.data_view_id.action).ok_or_else(|| {
                            format!("Missing item 3 {} in {}", field_name, self.data_view_id.id)
                        })?;

                        data_view.filter_results = array.clone();
                    }
                    Value::Object(_obj) => {}
                    _ => set_value_show(self, field_name, field_value_str, &element_id)?,
                }
            }
        }

        Ok(())
    }

    fn set_values(&mut self, server_connection: &ServerConnection, watcher: &Box<dyn DataViewWatch>, obj: &Value, element_id: Option<&HtmlElementId>) -> Result<(), Box<dyn std::error::Error>> {
        fn set_values_process(data_view: &mut DataView, element_id: Option<&HtmlElementId>, server_connection: &ServerConnection, watcher: &Box<dyn DataViewWatch>, obj: &Value) -> Result<(), Box<dyn std::error::Error>> {
            let data_view = if let Some(element_id) = element_id {
                if data_view.data_view_id.id != element_id.data_view_id.id {
                    data_view.childs.iter_mut().find(|data_view| data_view.data_view_id.schema_name == element_id.data_view_id.schema_name).ok_or_else(|| {
                        format!("Missing item 2 {} in {}", element_id.data_view_id.id, data_view.data_view_id.id)
                    })?
                } else {
                    data_view
                }
            } else {
                data_view
            };
/*
            let keys = if data_view.data_view_id.id != element_id.data_view_id.id {
                let data_view = data_view.childs.iter().find(|data_view| data_view.data_view_id.schema_name == element_id.data_view_id.schema_name).ok_or_else(|| {
                    format!("Missing item 2 {} in {}", element_id.data_view_id.id, data_view.data_view_id.id)
                })?;

                data_view.properties.iter().map(|item| item.0.to_string()).collect::<Vec<String>>()
            } else {
                data_view.properties.iter().map(|item| item.0.to_string()).collect::<Vec<String>>()
            };
*/
            let keys = data_view.properties.iter().map(|item| item.0.to_string()).collect::<Vec<String>>();

            for field_name in &keys {
                let value = obj.get(field_name).unwrap_or(&Value::Null);
                data_view.set_value(server_connection, watcher.as_ref(), field_name, value, element_id)?;
            }

            Ok(())
        }
        // const list = Object.entries(data_view.properties);
        // let filter = list.filter(([fieldName, field]) => field.hidden != true && field.readOnly != true && field.essential == true && field.type != "object" && field.type != "array" && data_view.instance[fieldName] == undefined);
        // if filter.length == 0) filter = list.filter(([fieldName, field]) => field.hidden != true && field.readOnly != true && field.essential == true && field.type != "object" && field.type != "array");
        // if filter.length == 0) filter = list.filter(([fieldName, field]) => field.hidden != true && field.readOnly != true && field.essential == true);
        // if filter.length == 0) filter = list.filter(([fieldName, field]) => field.hidden != true && field.readOnly != true);
        // if filter.length == 0) filter = list.filter(([fieldName, field]) => field.hidden != true);
        //self.get_document(self, obj, false);
        let obj = {
            let may_be_array = false;//true
            let ignore_null = true;
            let ignore_hidden = false;
            let only_primary_keys = false;
            server_connection.login_response.openapi.copy_fields_using_properties(&self.properties, &self.extensions, may_be_array, obj, ignore_null, ignore_hidden, only_primary_keys)?
        };
        //println!("[DEBUG - set_values - 1] {}.instance = {}", self.data_view_id.form_id, obj);
        set_values_process(self, element_id, server_connection, watcher, &obj)?;
/*
        for data_view in &mut self.childs {
            if data_view.typ == DataViewType::ObjectProperty && data_view.data_view_id.action == self.data_view_id.action {
                if let Some(obj) = obj.get(&data_view.data_view_id.schema_name) {
                    println!("\n[DEBUG - set_values - 2] {} : {}\n", data_view.data_view_id.id, obj);
                    data_view.set_values(server_connection, watcher, obj, None)?;
                }
            }
        }
*/
        Ok(())
    }

    pub async fn save(&self, server_connection: &mut ServerConnection) -> Result<Value, Box<dyn std::error::Error>> {
        let path = match &self.path {
            Some(path) => path,
            None => None.ok_or_else(|| format!("Missing path information"))?,
        };

        if self.data_view_id.action == DataViewProcessAction::New {
            server_connection.save(path, &self.params.instance).await
        } else {
            server_connection.update(path, &self.params.instance).await
        }
    }

    fn build_location_hash(data_view_id: &DataViewId, action: &DataViewProcessAction, params: &Value) -> Result<String, Box<dyn std::error::Error>> {
        let query_string = serde_qs::to_string(params).unwrap();

        let path = if let Some(schema_name) = &data_view_id.parent_schema_name {
            format!("{}-{}", schema_name.to_case(convert_case::Case::Snake), data_view_id.schema_name.to_case(convert_case::Case::Snake))
        } else {
            data_view_id.schema_name.to_case(convert_case::Case::Snake)
        };

        let query_string = query_string.replace("%2F", "/");

        Ok(format!("#!/app/{}/{}?{}", path, action, query_string))
    }

    fn build_go_to_field(&self, server_connection: &ServerConnection, element_id: &HtmlElementId, action: &DataViewProcessAction, obj: &Value) -> Result<Option<String>, Box<dyn std::error::Error>> {
        let field_name = element_id.field_name.as_ref().ok_or_else(|| format!("broken field_name"))?;

        if let Some(item) = server_connection.login_response.openapi.get_primary_key_foreign_with_schema(&self.properties, field_name, obj)? {
            //let action = element_id.action.as_ref().ok_or_else(|| format!("broken action"))?;
            let mut query_obj = json!({});

            if action == &DataViewProcessAction::Search {
                query_obj["origin"] = json!(format!("{}--{}", element_id.data_view_id.id, field_name));
                let filter = json!({});
                /*
                           if item.is_unique_key == false {
                               for (field_name, value) in item.primary_key {
                                   if value.is_null() == false {
                                       filter[field_name] = value;
                                   }
                               }
                           }
                */
                query_obj["filter"] = filter;
                //server_connection.useHistoryState = true;
                //window.history.replaceState(this.instance, "Edited values");
            } else {
                query_obj = item.primary_key;
            }

            let data_view_id = DataViewId::new(item.schema.clone(), None, action.clone());
            let url = DataView::build_location_hash(&data_view_id, action, &query_obj)?;
            Ok(Some(url))
        } else {
            let Some(value) = obj.get(field_name) else {
                return Ok(None);
            };

            let Some(value) = value.as_str() else {
                return Ok(None);
            };

            if value.starts_with("#") {
                return Ok(Some(value.to_string()));
            } else {
                return Ok(None);
            }
        }
    }

}

#[derive(Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LoginResponseClient {
    pub name: String,
    pub rufs_group_owner: String,
    pub groups: Vec<String>,
    pub roles: Vec<Role>,
    pub ip: String,
    pub path: String,
    pub jwt_header: String,
    pub title: String,
    pub openapi: OpenAPI,
}

#[derive(Default)]
pub struct ServerConnection {
    http_rest: HttpRestRequest,
    pub login_response: LoginResponseClient,
    service_map: HashMap<String, Service>,
    //pathname: String,
    //remote_listeners: Vec<dyn RemoteListener>,
    //web_socket :Option<WebSocket>,
}

/*
TODO : no processo de login buscar somente as alterações.
https://dba.stackexchange.com/questions/233735/track-all-modifications-to-a-postgresql-table
 */
impl ServerConnection {
    pub fn new(server_url: &str) -> Self {
        Self {
            http_rest: HttpRestRequest::new(server_url),
            ..Default::default()
        }
    }

    pub fn update_list(&mut self, schema_name: &str, primary_key: &Value, value: Value) -> Result<usize, Box<dyn std::error::Error>> {
        let service = self.service_map.get(schema_name).ok_or_else(|| format!("Missing service {} in service_map", schema_name))?;
        let str = service.build_item_str(self, &value)?;

        if let Some(pos) = service.find_pos(&primary_key)? {
            let service = self.service_map.get_mut(schema_name).ok_or_else(|| format!("Missing service {} in service_map", schema_name))?;
            service.list_str[pos] = str;
            service.list[pos] = value;
            Ok(pos)
        } else {
            let primary_key_hash = service.get_primary_key_hash(&value)?;
            let service = self.service_map.get_mut(schema_name).ok_or_else(|| format!("Missing service {} in service_map", schema_name))?;
            let pos = service.list.len();
            service.list_str.push(str);
            service.list.push(value);
            service.map_list.insert(primary_key_hash, pos);
            Ok(pos)
        }
    }

    async fn get(&mut self, schema_name: &str, primary_key: &Value) -> Result<Option<Value>, Box<dyn std::error::Error>> {
        let service = self.service_map.get(schema_name).ok_or_else(|| format!("Missing service {} in service_map", schema_name))?;
        let pos = service.find_pos(primary_key)?;

        let pos = if let Some(pos) = pos {
            pos
        } else {
            #[cfg(debug_assertions)]
            if service.list_str.len() > 0 {
                println!("Missing element with primary key ({primary_key}) in list :");

                for ele in &service.list {
                    println!("{ele}");
                }
            }

            let value = self.http_rest.get(&service.path, primary_key).await?;

            match &value {
                Value::Array(list) => {
                                if list.len() == 1 {
                                    let value = list.first().ok_or("broken")?;
                                    self.update_list(schema_name, primary_key, value.clone())?
                                } else if list.len() == 0 {
                                    return Ok(None);
                                } else {
                                    return Err(format!("Missing parameter {} in query string {}.", "primary_key", ""))?;
                                }
                            }
                Value::Null => return Err("Expected array response, found Null")?,
                Value::Bool(_) => return Err("Expected array response, found Bool")?,
                Value::Number(_number) => return Err("Expected array response, found Number")?,
                Value::String(_) => return Err("Expected array response, found String")?,
                Value::Object(_map) => {
                    self.update_list(schema_name, primary_key, value.clone())?
                },
            }            
        };

        let service = self.service_map.get(schema_name).ok_or_else(|| format!("Missing service {} in service_map", schema_name))?;
        let ret = service.list.get(pos).ok_or("broken")?;
        Ok(Some(ret.clone()))
    }

    async fn save(&mut self, path: &str, item_send: &Value) -> Result<Value, Box<dyn std::error::Error>> {
        let schema_name = &path[1..].to_string().to_case(convert_case::Case::Camel);
        let service = self.service_map.get_mut(schema_name).ok_or_else(|| format!("[ServerConnection.save({})] missing service {}", path, schema_name))?;
        let schema_place = SchemaPlace::Request; //data_view.schema_place
        let method = "post"; //data_view.method
        let data_out = self.login_response.openapi.copy_fields(&service.path, method, &schema_place, false, item_send, false, false, false)?;
        let data_in = self.http_rest.save(&service.path, &data_out).await?;
        let primary_key = &service.get_primary_key(&data_in).ok_or_else(|| format!("[ServerConnection.save] {}  - data_in : Missing primary key", schema_name))?;
        self.update_list(schema_name, primary_key, data_in.clone())?;
        Ok(data_in)
    }

    async fn update(&mut self, path: &str, item_send: &Value) -> Result<Value, Box<dyn std::error::Error>> {
        let schema_name = &path[1..].to_string().to_case(convert_case::Case::Camel);
        let service = self.service_map.get_mut(schema_name).unwrap();
        let schema_place = SchemaPlace::Request; //data_view.schema_place
        let method = "put"; //data_view.method
        let data_out = self.login_response.openapi.copy_fields(&service.path, method, &schema_place, false, item_send, false, false, false)?;
        let primary_key = &service.get_primary_key(&data_out).ok_or_else(|| format!("[ServerConnection.update] {}  - data_out : Missing primary key", schema_name))?;
        let data_in = self.http_rest.update(&service.path, primary_key, &data_out).await?;
        let primary_key = &service.get_primary_key(&data_in).ok_or_else(|| format!("[ServerConnection.update] {} - data_in : Missing primary key", schema_name))?;
        self.update_list(schema_name, primary_key, data_in.clone())?;
        Ok(data_in)
    }

    async fn remove(&mut self, schema_name: &str, primary_key: &Value) -> Result<(), Box<dyn std::error::Error>> {
        let service = self.service_map.get_mut(schema_name).ok_or_else(|| format!("Missing service {} in service_map", schema_name))?;
        let _res_data = self.http_rest.remove(&service.path, primary_key).await?;
        
        if let Some(pos) = service.find_pos(&primary_key)? {
            service.list.remove(pos);
        }

        Ok(())
    }
    /*
        async fn patch(&self, item_send :&Value) -> Value {
            let data = self.http_rest.patch(self.path, self.openapi.copy_fields(self.path, self.method, self.schema_place, item_send)).await;
            self.update_list(&data);
            data
        }
    */
    /*
        fn getDocument(service, obj, merge, tokenPayload) {
            const getPrimaryKeyForeignList = (schema, obj) => {
                let list = [];

                for [fieldName, field] of Object.entries(schema.properties) {
                    if field.$ref != undefined {
                        let item = self.getPrimaryKeyForeign(schema, fieldName, obj);

                        if item.valid == true && list.find(candidate => candidate.fieldName == fieldName).is_none() {
                            list.push({"fieldName": fieldName, item});
                        }
                    }
                }

                return list;
            }

            let document;

            if merge != true {
                document = {};
            } else {
                document = obj;
            }

            let promises = [];
            // One To One
            {
                const next = (document, list) => {
                    if list.length == 0) return;
                    let data = list.shift();
                    let schemaRef = self.getSchema(data.item.schema);

                    if schemaRef.is_none() {
                        console.error(data);
                        self.getSchema(data.item.schema);
                    }

                    let promise;

                    if Object.entries(data.item.primary_key).length > 0 {
                        promise = self.get(schemaRef.name, data.item.primary_key);
                    } else {
                        promise = Promise.resolve({});
                    }


                    return promise.
                    then(objExternal => document[data.fieldName] = objExternal).
                    catch(err => console.error(err)).
    //				then(() => next(document, list));
                    finally(() => next(document, list));
                }

                let listToGet = getPrimaryKeyForeignList(service, obj);
                promises.push(next(document, listToGet));
            }
            // One To Many
            {
                let dependents = self.openapi.get_dependents(service.name, true, self.services);

                for item of dependents {
                    let rufsServiceOther = self.getSchema(item.schema, tokenPayload);
                    if rufsServiceOther == null) continue;
                    let field = rufsServiceOther.properties[item.field];
                    let foreignKey = Object.fromEntries(self.openapi.get_foreign_key(rufsServiceOther.name, item.field, obj));
                    // TODO : check to findRemote
                    promises.push(service.find(foreignKey).then(list => document[field.document] = list));
                }
            }

            return Promise.all(promises).then(() => document);
        }

        fn getDocument(service, obj, merge, tokenData) {
            return super.getDocument(service, obj, merge, tokenData).then(() => {
                if service.primary_keys.length > 0 {
                    let primaryKey = service.get_primary_key(obj);

                    if primaryKey != null {
                        let pos = service.find_pos(primaryKey);

                        if pos >= 0 {
                            if service.updateListStr != undefined {
                                service.updateListStr({data: obj, oldPos: pos, newPos: pos});
                            } else {
                                console.error(`[${self.constructor.name}.getDocument()] : missing updateListStr`);
                            }
                        }
                    }
                }
            });
        }

        fn getDocuments(service, list, index) {
            if list == null || list.length == 0) return Promise.resolve();
            if index == null) index = 0;
            if index >= list.length) return Promise.resolve();
            let item = list[index];
            console.log(`[${self.constructor.name}.getDocuments(${service.name}, ${index})] : updating references to register ${index}, item = ${JSON.stringify(item)}, list = `, list);
            return self.getDocument(service, item, false).then(() => self.getDocuments(service, list, ++index));
        }
    */
    // devolve o rufsService apontado por field
    fn get_foreign_service<'a>(&'a self, service: &Service, field_name: &str, debug: bool) -> Option<&'a Service> {
        // TODO : refatorar consumidores da função getForeignService(field), pois pode haver mais de uma referência
        let field = self.login_response.openapi.get_property(&service.schema_name, field_name);

        match field {
            Some(field) => {
                match field.schema_data.extensions.get("x-$ref") {
                    Some(reference) => {
                        let reference = reference.as_str().unwrap();
                        let schema_name = OpenAPI::get_schema_name_from_ref(reference)/*.to_case(convert_case::Case::Snake) */;
                        self.service_map.get(&schema_name)
                    }
                    None => {
                        #[cfg(debug_assertions)]
                        if debug {
                            self.get_foreign_service(service, field_name, true);
                        }

                        None
                    }
                }
            }
            None => {
                if debug {
                    self.get_foreign_service(service, field_name, true)
                } else {
                    None
                }
            }
        }
    }

    /*
        fn clear_remote_listeners(&mut self) {
            self.remote_listeners.clear();
        }

        fn add_remote_listener(&self, listener_instance: &RemoteListener) {
            self.remote_listeners.push(listener_instance);
        }
    */
    // private -- used in login()
    fn web_socket_connect(&self, _path: &str) {
        /*
        struct WebSocketData {
            service :String,
            action :String,
            primary_key : Value,
        }
        */
        // Open a WebSocket connection
        // 'wss://localhost:8443/xxx/websocket'
        /*
        let mut url = if self.http_rest.url.starts_with("https://") {
            format!("wss://{}", self.http_rest.url[..8].to_string())
        } else if self.http_rest.url.starts_with("http://") {
            format!("ws://{}", self.http_rest.url[..7].to_string())
        } else {
            format!("ws://{}", self.http_rest.url.to_string())
        };

        if url.ends_with("/") == false {
            url = url + "/";
        }

        url = url + path;

        if url.ends_with("/") == false {
            url = url + "/";
        }
        */
        /*
        let url = url + "websocket";
        self.web_socket = WebSocket::new(url);

        self.web_socket.onopen = |event| self.web_socket.send(self.http_rest.get_token());

        self.web_socket.onmessage = |event| {
            let item: WebSocketData = serde_json::from_str(event.data);
            //console.log("[ServerConnection] webSocketConnect : onMessage :", item);
            if let Some(service) = self.services.get(item.service) {
                if item.action == "delete" {
                    if let Some(primary_key) = service.find_one(item.primary_key) {
                        self.remove_internal(&item.service, primary_key);
                    } else {
                        //console.log("[ServerConnection] webSocketConnect : onMessage : delete : alread removed", item);
                    }
                } else {
                    if let Some(res) = self.get(&item.service, &item.primary_key, true).await {
                        /*
                        for listener in self.remote_listeners {
                            listener.on_notify(&item.service, &item.primary_key, &item.action);
                        }
                        */
                    }
                }
            }
        };
        */
    }
    // public
    pub async fn login_from_response(&mut self, login_response: LoginResponseClient) -> Result<(), Box<dyn std::error::Error>> {
        self.http_rest.token = Some(login_response.jwt_header.clone());
        self.login_response = login_response;

        self.service_map.clear();
        let mut list_dependencies = vec![];
        // depois carrega os serviços autorizados
        for role in self.login_response.roles.clone() {
            let schema_name = role.path[1..].to_string().to_case(convert_case::Case::Camel);
            let service = Service::new(&self.login_response.openapi, &role.path)?;
            self.service_map.insert(schema_name.clone(), service);
            self.login_response.openapi.get_dependencies(&schema_name, &mut list_dependencies);

            if list_dependencies.contains(&schema_name) == false {
                list_dependencies.push(schema_name);
            }
        }

        for schema_name in list_dependencies {
            //console.log(`login ${schemaName}`)
            let service = self.service_map.get(&schema_name);

            if let Some(service) = service {
                if &service.method_response == "get" {
                    let (map_list, list, list_str) = service.query_remote(self, &Value::Null).await?;
                    let service = self.service_map.get_mut(&schema_name).unwrap();
                    service.map_list = map_list;
                    service.list = list;
                    println!("login 1.1 : service {}, list_str.len = {}", schema_name, list_str.len());
                    service.list_str = list_str;
                }
            }
        }

        self.web_socket_connect("websocket");
        Ok(())
    }

    pub async fn login(&mut self, path: &str, username: &str, password: &str) -> Result<(), Box<dyn std::error::Error>> {
        let login_response = self.http_rest.login(path, username, password).await?;
        self.login_from_response(login_response).await
    }
    // public
    /*
        fn logout(&mut self) {
            // limpa todos os dados da sessão anterior
            //self.web_socket.close();
               //self.http_rest.set_token(None);
            //self.services.clear();
        }
    */
}

pub trait DataViewWatch: std::marker::Sync + Send {
    fn check_set_value(&self, data_view: &mut DataView, element_id: &HtmlElementId, server_connection: &ServerConnection, field_name: &str, field_value: &Value) -> Result<bool, Box<dyn std::error::Error>>;
    fn check_save(&self, data_view: &mut DataView, element_id: &HtmlElementId, server_connection: &ServerConnection) -> Result<(bool, DataViewProcessAction), Box<dyn std::error::Error>>;
    fn menu(&self) -> Value;
}

//#[derive(Default)]
pub struct DataViewManager<'a> {
    pub server_connection: ServerConnection,
    data_view_map: HashMap<String, DataView>,
    watcher: &'a Box<dyn DataViewWatch>,
}

#[macro_export]
macro_rules! function {
    () => {{
        fn f() {}
        fn type_name_of<T>(_: T) -> &'static str {
            std::any::type_name::<T>()
        }
        let name = type_name_of(f);

        // Find and cut the rest of the path
        match &name[..name.len() - 3].rfind(':') {
            Some(pos) => &name[pos + 1..name.len() - 3],
            None => &name[..name.len() - 3],
        }
    }};
}

#[macro_export]
macro_rules! data_view_get {
    ($data_view_manager:tt, $element_id:tt) => {{
        let id = &$element_id.data_view_id;
        let data_view_map: &std::collections::HashMap<String, crate::client::DataView> = &$data_view_manager.data_view_map;

        let data_view = if let Some(parent_id) = &id.parent_id {
            let data_view = data_view_map.get(parent_id).ok_or_else(|| {
                let keys = data_view_map.keys().map(|item| format!("{},", item)).collect::<String>();
                format!("Missing data_view_map.get({}).\nOptions : {}", parent_id, keys)
            })?;
            data_view.childs.iter().find(|item| item.data_view_id.id == id.id).ok_or_else(|| {
                let keys = data_view.childs.iter().map(|item| item.data_view_id.id.clone()).collect::<String>();
                format!("Missing item {} in data_view {}, options : {}", id.id, parent_id, keys)
            })?
        } else {
            data_view_map.get(&$element_id.data_view_id.id).ok_or_else(|| {
                format!("[process_click_target] Missing form {} in data_view_manager (2).", id.id)
            })?
        };

        data_view
    }};
}

#[macro_export]
macro_rules! data_view_get_mut {
    ($data_view_manager:tt, $element_id:tt) => {{
        let id = &$element_id.data_view_id;

        let data_view = if let Some(parent_id) = &id.parent_id {
            let data_view = $data_view_manager.data_view_map.get_mut(parent_id).ok_or_else(|| {
                format!("[{} - data_view_get_mut] Missing parent schema {:?} in data_view_manager", function!(), id.parent_id)
            })?;
            data_view.childs.iter_mut().find(|item| item.data_view_id.id == id.id).ok_or_else(|| {
                format!("Missing item {} in data_view {}", id.id, parent_id)
            })?
        } else {
            $data_view_manager.data_view_map.get_mut(&$element_id.data_view_id.id).ok_or_else(|| {
                format!("[process_click_target] Missing form {} in data_view_manager (2).", id.id)
            })?
        };

        //println!("[{} - data_view_get_mut] : {:?}", function!(), $element_id);
        data_view
    }};
}

#[macro_export]
macro_rules! data_view_get_parent_mut {
    ($data_view_manager:tt, $element_id:tt) => {{
        let data_view_id = &$element_id.data_view_id;
        
        let data_view = if let Some(parent_id) = &data_view_id.parent_id {
            $data_view_manager.data_view_map.get_mut(parent_id).ok_or_else(|| {
                format!("[data_view_get_parent_mut] Missing parent schema {:?} in data_view_manager", parent_id)
            })?
        } else {
            $data_view_manager.data_view_map.get_mut(&data_view_id.id).ok_or_else(|| {
                format!("[data_view_get_parent_mut] Missing parent schema {:?} in data_view_manager", data_view_id.id)
            })?
        };

        println!("[{} - data_view_get_parent_mut] : {:?}", function!(), $element_id);
        data_view
    }};
}

#[derive(Deserialize)]
pub struct LoginDataIn {
    user: String,
    password: String
}

impl DataViewManager<'_> {
    pub fn new(server_url: &str, watcher: &'static Box<dyn DataViewWatch>) -> Self {
        let server_connection = ServerConnection::new(server_url);
        Self {
            server_connection,
            data_view_map: Default::default(),
            watcher,
        }
    }

    pub async fn login(&mut self, path: &str, params: Value) -> Result<Value, Box<dyn std::error::Error>> {
        let data_in = serde_json::from_value::<LoginDataIn>(params)?;
        self.server_connection.login(path, &data_in.user, &data_in.password).await?;
        Ok(json!({"menu": self.watcher.menu(), "path": self.server_connection.login_response.path, "jwt_header": self.server_connection.login_response.jwt_header}))
    }

    pub async fn login_from_response(&mut self, params: Value) -> Result<Value, Box<dyn std::error::Error>> {
        let data_in = serde_json::from_value::<LoginResponseClient>(params)?;
        self.server_connection.login_from_response(data_in).await?;
        Ok(json!({"menu": self.watcher.menu(), "path": self.server_connection.login_response.path, "jwt_header": self.server_connection.login_response.jwt_header}))
    }

    async fn process_data_view_action(&mut self, element_id: &HtmlElementId, params_search: &DataViewParams, params_extra: &Value, data_view_response :&mut DataViewResponse) -> Result<(), Box<dyn std::error::Error>> {
        fn set_filter_range(data_view: &mut DataView, field_name: &str, range: &str) {
            let period_labels = [" minuto ", " hora ", " dia ", " semana ", " quinzena ", " mês ", " ano "];
            let periods = [60, 3600, 86400, 7 * 86400, 15 * 86400, 30 * 86400, 365 * 86400];
            let mut period = 1;

            for i in 0..period_labels.len() {
                if range.contains(period_labels[i]) {
                    period = periods[i] * 1000;
                    break;
                }
            }

            let now = chrono::Local::now();
            let now_period_trunc = (now.timestamp() / period) * period;
            let mut date_end = Local.timestamp_opt(now_period_trunc + period, 0).unwrap();

            let date_ini = if range.contains(" corrente ") {
                Local.timestamp_opt(now_period_trunc, 0).unwrap()
            } else if range.contains(" anterior ") {
                date_end = Local.timestamp_opt(now_period_trunc, 0).unwrap();
                Local.timestamp_opt(now_period_trunc - period, 0).unwrap()
            } else {
                Local.timestamp_opt(now.timestamp() - period, 0).unwrap()
            };

            let now_date = Local.with_ymd_and_hms(now.year(), now.month(), now.day(), 0, 0, 0).unwrap();
            let day_active_start = now_date.clone();
            let day_last_start = now_date.checked_sub_days(Days::new(1)).unwrap();
            let week_active_start = now_date.checked_sub_days(Days::new(now_date.weekday().num_days_from_monday().into())).unwrap();
            let week_last_start = week_active_start.checked_sub_days(Days::new(7)).unwrap();
            let month_active_start = Local.with_ymd_and_hms(now.year(), now.month(), 1, 0, 0, 0).unwrap();
            let month_last_start = month_active_start.checked_sub_months(Months::new(1)).unwrap();
            let year_active_start = Local.with_ymd_and_hms(now.year(), 1, 1, 0, 0, 0).unwrap();
            let year_last_start = Local.with_ymd_and_hms(now.year() - 1, 1, 1, 0, 0, 0).unwrap();

            let (date_ini, date_end) = match range {
                "dia corrente" => (day_active_start, day_active_start.checked_add_days(Days::new(1)).unwrap()),
                "dia anterior" => (day_last_start, day_active_start),
                "semana corrente" => (week_active_start, week_active_start.checked_add_days(Days::new(7)).unwrap()),
                "semana anterior" => (week_last_start, week_active_start),
                "quinzena corrente" => {
                    let date_ini = if now.day() <= 15 {
                        month_active_start
                    } else {
                        Local.with_ymd_and_hms(now.year(), now.month(), 15, 0, 0, 0).unwrap()
                    };

                    (date_ini, date_ini.checked_add_days(Days::new(15)).unwrap())
                }
                "quinzena anterior" => {
                    let date_end = if now.day() <= 15 {
                        month_active_start
                    } else {
                        Local.with_ymd_and_hms(now.year(), now.month(), 15, 0, 0, 0).unwrap()
                    };

                    let date_ini = if date_end.day() > 15 { date_end.with_day(15).unwrap() } else { date_end.with_day(1).unwrap() };

                    (date_ini, date_end)
                }
                "mês corrente" => (month_active_start, month_active_start.checked_add_months(Months::new(1)).unwrap()),
                "mês anterior" => (month_last_start, month_active_start),
                "ano corrente" => (year_active_start, year_active_start.checked_add_months(Months::new(12)).unwrap()),
                "ano anterior" => (year_last_start, year_active_start),
                _ => (date_ini, date_end),
            };

            data_view.params.filter_range_min[field_name] = json!(date_ini.to_rfc3339());
            data_view.params.filter_range_max[field_name] = json!(date_end.to_rfc3339());
        }

        fn build_field_filter_results(data_view: &mut DataView, server_connection: &ServerConnection) -> Result<(), Box<dyn std::error::Error>> {
            // faz uma referencia local a field.filter_results_str, para permitir opção filtrada, sem alterar a referencia global
            for (field_name, field) in &data_view.properties {
                let field = field.as_item().unwrap();
                let extensions = &field.schema_data.extensions;

                let (list, list_str) = if let Some(reference) = extensions.get("x-$ref") {
                    let reference = reference.as_str().ok_or_else(|| format!("reference is not string"))?;

                    if let Some(_service_ref) = server_connection.service_map.get(reference) {
                        //data_view.serverConnection.getDocuments(service_ref, service.list).await;
                    }

                    let service = server_connection.service_map.get(&data_view.data_view_id.schema_name).ok_or_else(|| format!(
                        "[build_field_filter_results] Missing service {} in server_connection.service_map.",
                        data_view.data_view_id.schema_name
                    ))?;

                    if let Some(service) = server_connection.get_foreign_service(service, field_name, true) {
                        let mut filter = if let Some(filter) = data_view.field_filter_results.get(field_name) {
                            filter.clone()
                        } else {
                            json!({})
                        };

                        if filter.as_object().ok_or_else(|| format!("filter is not object"))?.is_empty() {
                            if let Some(pos) = reference.chars().position(|c| c == '?') {
                                let primary_key = queryst::parse(&reference[pos..]).unwrap();

                                for (field_name, value) in primary_key.as_object().unwrap() {
                                    if let Some(value) = value.as_str() {
                                        if value.starts_with("*") {
                                            let value = json!(value[1..]);
                                            let field = data_view.properties.get(field_name).ok_or_else(|| format!("[build_field_filter_results]"))?;
                                            let field = field.as_item().ok_or_else(|| format!("as_ref"))?;
                                            filter[field_name] = server_connection.login_response.openapi.copy_value_field(field, true, &value).unwrap();
                                        }
                                    }
                                }
                            }
                        }

                        if filter.as_object().ok_or_else(|| format!("filter is not object"))?.is_empty() == false {
                            let list = vec![];
                            let list_str = vec![];

                            for _candidate in &service.list {
                                // if Filter::match(filter, candidate) {
                                //     list.push(candidate);
                                //     let str = rufs_service.list_str[i];
                                //     list_str.push(str);
                                // }
                            }

                            (list, list_str)
                        } else {
                            (service.list.clone(), service.list_str.clone())
                        }
                    } else {
                        println!("[build_field_filter_results] don't have acess to service {}", reference);
                        (vec![], vec![])
                    }
                } else if let Some(enumeration) = extensions.get("x-enum") {
                    let enumeration = enumeration.as_array().ok_or_else(|| format!("x-enum is not array"))?;

                    let list_str = if let Some(enum_labels) = extensions.get("x-enumLabels") {
                        enum_labels.as_array().unwrap().iter().map(|s| s.as_str().unwrap().to_string()).collect()
                    } else {
                        enumeration.iter().map(|s| s.to_string()).collect()
                    };

                    (enumeration.clone(), list_str)
                } else {
                    (vec![], vec![])
                };

                data_view.field_results.insert(field_name.clone(), list.clone());
                data_view.field_results_str.insert(field_name.clone(), list_str.clone());
            }

            Ok(())
        }

        #[cfg_attr(target_arch = "wasm32", async_recursion::async_recursion(?Send))]
        #[cfg_attr(not(target_arch = "wasm32"), async_recursion::async_recursion)]
        async fn data_view_get(watcher: &Box<dyn DataViewWatch>, data_view: &mut DataView, server_connection: &mut ServerConnection, primary_key: &Value, element_id: Option<&HtmlElementId>) -> Result<(), Box<dyn std::error::Error>> {
            let schema_name = &data_view.data_view_id.schema_name;
            
            let primary_key = {
                let service = server_connection.service_map.get(schema_name).ok_or_else(|| format!("[data_view_get] Missing service {} in server_connection.service_map.", data_view.data_view_id.schema_name))?;
                let schema_place = SchemaPlace::Parameter;
                let method = "get";
                server_connection.login_response.openapi.copy_fields(&service.path, method, &schema_place, false, primary_key, false, false, true)?        
            };
            
            let Some(value) = server_connection.get(schema_name, &primary_key).await? else {
                return Ok(())
            };
            
            for data_view_item in data_view.childs.iter_mut() {
                let DataViewType::Child(dependent) = &data_view_item.typ else {
                    continue;
                };

                let (_fkd, foreign_key) = server_connection.login_response.openapi.get_foreign_key(&data_view_item.properties/*&item.schema*/, &data_view_item.extensions, &dependent.field, &primary_key)?.ok_or_else(|| format!("Invalid FK"))?;

                if data_view_item.data_view_id.action == DataViewProcessAction::New {
                    for (field_name, value) in foreign_key.as_object().ok_or("foreign_key is not object")? {
                        let property = data_view_item.properties.get_mut(field_name).ok_or_else(|| format!("Missing field {} in {}", field_name, data_view.data_view_id.schema_name))?;
    
                        match property {
                            ReferenceOr::Reference { reference: _ } => todo!(),
                            ReferenceOr::Item(property) => property.schema_data.default = Some(value.clone())
                        }
                    }
    
                    //let element_id = HtmlElementId::new_with_data_view_id(data_view_item.data_view_id.clone(), None, None, None);
                    data_view_item.set_values(server_connection, watcher, &foreign_key, None)?;
                }

                if data_view_item.path.is_some() {
                    data_view_item.filter_results.clear();
                    let schema_name = &data_view_item.data_view_id.schema_name;
                    let service = server_connection.service_map.get(schema_name).ok_or_else(|| format!("Missing service"))?;

                    if data_view_item.is_one_to_one {
                        if data_view_item.data_view_id.action != DataViewProcessAction::Search {
                            data_view_get(watcher, data_view_item, server_connection, &foreign_key, None).await?;
                        }
                    } else {
                        if data_view_item.data_view_id.action == DataViewProcessAction::Search {
                            for item in &service.list {
                                if crate::data_store::Filter::check_match_exact(item, &foreign_key)? {
                                    data_view_item.filter_results.push(item.clone());
                                }
                            }
                        }
                    }                    
                }        
            }

            data_view.params.primary_key = Some(primary_key);
            data_view.set_values(server_connection, watcher, &value, element_id)
        }

        let parent_id = if let Some(parent_id) = &element_id.data_view_id.parent_id {
            parent_id
        } else {
            &element_id.data_view_id.id
        };

        let is_first = if self.data_view_map.contains_key(parent_id) == false {
            let path = if let Some(parent) = &element_id.data_view_id.parent_schema_name {
                format!("/{}", parent.to_case(convert_case::Case::Snake))
            } else {
                format!("/{}", element_id.data_view_id.schema_name.to_case(convert_case::Case::Snake)).replace("/v_", "/v")
            };

            let mut data_view = DataView::new(&path, DataViewType::Primary, None, element_id.data_view_id.action.clone());
            data_view.set_schema(&self.server_connection)?;

            let action_childs = if data_view.data_view_id.action == DataViewProcessAction::Edit {
                vec![DataViewProcessAction::New, data_view.data_view_id.action, DataViewProcessAction::Search]
            } else {
                vec![data_view.data_view_id.action, DataViewProcessAction::Search]
            };

            if data_view.data_view_id.action != DataViewProcessAction::New && data_view.data_view_id.action != DataViewProcessAction::Search {
                let dependents = self.server_connection.login_response.openapi.get_dependents(&data_view.data_view_id.schema_name, false);

                for dependent in &dependents {
                    if let Some(field) = self.server_connection.login_response.openapi.get_property(&dependent.schema, &dependent.field) {
                        let extensions = &field.schema_data.extensions;

                        if let Some(_enumeration) = extensions.get("x-title") {
                            let path = format!("/{}", dependent.schema.to_case(convert_case::Case::Snake));
                            let service = self.server_connection.service_map.get(&dependent.schema).ok_or_else(|| format!("Missing service"))?;

                            for action in &action_childs {
                                let mut data_view_item = DataView::new(&path, DataViewType::Child(dependent.clone()), Some(data_view.data_view_id.clone()), action.clone());

                                if service.primary_keys.len() == 1 && service.primary_keys.contains(&dependent.field) {
                                    data_view_item.is_one_to_one = true;
                                }
    
                                data_view_item.set_schema(&self.server_connection)?;
                                data_view.childs.push(data_view_item);
                            }
                        }
                    }
                }
            }

            for (field_name, field) in &data_view.properties {
                if data_view.childs.iter().find(|child| &child.data_view_id.schema_name == field_name).is_some() {
                    // TODO : verificar se a duplicidade pode ser um bug
                    continue;
                }

                let field = field.as_item().ok_or_else(|| format!("data_view_get 1 : context"))?;

                match &field.schema_kind {
                    SchemaKind::Type(typ) => match &typ {
                        Type::Array(array) => {
                            let field = array.items.as_ref().ok_or_else(|| format!("data_view_get 2 : context"))?;
                            let field = field.as_item().ok_or_else(|| format!("data_view_get 3 : context"))?;

                            let properties = match &field.schema_kind {
                                SchemaKind::Type(typ) => match typ {
                                    Type::Object(schema) => {
                                        Some(&schema.properties)
                                    }
                                    _ => None
                                },
                                SchemaKind::Any(schema) => {
                                    Some(&schema.properties)
                                }
                                _ => None,
                            };

                            if let Some(properties) = properties {
                                for action in &action_childs {
                                    let mut data_view_item = DataView::new(field_name, DataViewType::ObjectProperty, Some(data_view.data_view_id.clone()), action.clone());
                                    data_view_item.properties = properties.clone();
                                    data_view.childs.push(data_view_item);
                                }
                            }
                        }
                        _ => {}
                    },
                    _ => {}
                }
            }

            for data_view in &mut data_view.childs {
                // TODO : verificar se não está processando em actions desnecessários
                build_field_filter_results(data_view, &self.server_connection)?;
                data_view_response.forms.insert(data_view.data_view_id.id.clone(), data_view.state.clone());
            }

            self.data_view_map.insert(data_view.data_view_id.id.clone(), data_view);
            true
        } else {
            false
        };

        let data_view = data_view_get_mut!(self, element_id);
        
        if is_first {
            build_field_filter_results(data_view, &self.server_connection)?;
        }

        match &data_view.data_view_id.action {
            DataViewProcessAction::New => {
                if params_search.instance.as_object().ok_or_else(|| format!("broken obj"))?.is_empty() == false {
                    data_view.set_values(&self.server_connection, &self.watcher, &params_search.instance, Some(element_id))?;
                } else {
                    data_view.set_values(&self.server_connection, &self.watcher, params_extra, Some(element_id))?;
                }
            }
            DataViewProcessAction::Edit | DataViewProcessAction::View => {
                if data_view.path.is_some() {
                    let primary_key = if let Some(primary_key) = &params_search.primary_key {
                        primary_key
                    } else {
                        params_extra
                    };

                    data_view_get(&self.watcher, data_view, &mut self.server_connection, primary_key, Some(element_id)).await?
                } else {
                    data_view.set_values(&self.server_connection, &self.watcher, params_extra, Some(element_id))?;
                }
            }
            _ => {
                data_view.params.origin = params_search.origin.clone();

                {
                    let mut have_filter = false;

                    for (field_name, value) in params_search.filter_range.as_object().ok_or_else(|| format!("broken obj"))? {
                        have_filter = true;
                        
                        if let Some(value) = value.as_str() {
                            if value.len() > 0 {
                                set_filter_range(data_view, field_name, value);
                            }
                        }
                    }

                    if params_search.filter.as_object().ok_or_else(|| format!("bron obj"))?.is_empty() == false {
                        have_filter = true;
                        data_view.params.filter = params_search.filter.clone();
                    }

                    if params_search.filter_range_min.as_object().ok_or_else(|| format!("broken ok"))?.is_empty() == false {
                        have_filter = true;
                        data_view.params.filter_range_min = params_search.filter_range_min.clone();
                    }

                    if params_search.filter_range_max.as_object().ok_or_else(|| format!("broken ok"))?.is_empty() == false {
                        have_filter = true;
                        data_view.params.filter_range_max = params_search.filter_range_max.clone();
                    }

                    if have_filter {
                        let service = self.server_connection.service_map.get(&data_view.data_view_id.schema_name).ok_or_else(|| format!("Missing service in service_map"))?;
                        data_view.apply_filter(&service.list);
                    }
                }

                if params_search.aggregate.as_object().ok_or_else(|| format!("broken obj"))?.is_empty() == false {
                    data_view.apply_aggregate(&self.server_connection, &params_search.aggregate)?;
                }

                if params_search.sort.is_empty() == false {
                    data_view.params.sort = params_search.sort.clone();
                    data_view.apply_sort()?;
                }
            }
        }

        if is_first {
            let html = DataView::build_form(data_view, element_id.data_view_id.action)?;
            #[cfg(debug_assertions)]
            #[cfg(not(target_arch = "wasm32"))]
            std::fs::write(format!("/tmp/{}.html", element_id.data_view_id.id), &html)?;
            data_view_response.html[&element_id.data_view_id.id] = json!(html);
        }

        if data_view.data_view_id.action == DataViewProcessAction::Search {
            let table = DataView::build_table(&self.server_connection, data_view, params_search)?;
            data_view_response.tables[&data_view.data_view_id.id] = json!(table);
            return Ok(());
        }

        for data_view in &mut data_view.childs {
            // TODO : verificar se não está processando em actions desnecessários
            if data_view.filter_results.len() > 0 {
                let table = DataView::build_table(&self.server_connection, data_view, params_search)?;
                data_view_response.tables[&data_view.data_view_id.id] = json!(table);
            }
        }

        if data_view.data_view_id.action == DataViewProcessAction::Edit {
            for data_view in &mut data_view.childs {
                match data_view.data_view_id.action {
                    DataViewProcessAction::New => {},
                    DataViewProcessAction::Edit => {
                        if data_view.typ == DataViewType::ObjectProperty {
                            data_view.state.hidden = false;
                            data_view_response.forms.insert(data_view.data_view_id.id.clone(), data_view.state.clone());
                        }
                    },
                    DataViewProcessAction::View => {},
                    DataViewProcessAction::Search => {
                        data_view.state.hidden = false;
                        data_view_response.forms.insert(data_view.data_view_id.id.clone(), data_view.state.clone());
                    },
                    DataViewProcessAction::Filter => {},
                    DataViewProcessAction::Aggregate => {},
                    DataViewProcessAction::Sort => {},
                }
            }
        }

        data_view.state.hidden = false;
        data_view_response.forms.insert(data_view.data_view_id.id.clone(), data_view.state.clone());
        data_view.build_changes(&mut data_view_response.changes)?;
        Ok(())
    }

    pub fn parse_query_string(query_string :&str) -> Result<(DataViewParams, Value), Box<dyn std::error::Error>> {
        let pairs = if query_string.len() > 0 {
            let str = &query_string[1..];
            nested_qs::from_str::<Value>(str)?
        } else {
            json!({})
        };

        if let Some(obj_in) = pairs.as_object() {
            let mut obj_out = json!({});

            for (field_name, value) in obj_in {
                let fields = field_name.split(".");
                let mut obj_out = &mut obj_out;

                for field_name in fields {
                    if obj_out.get(field_name).is_none() {
                        obj_out[field_name] = json!({});
                    }

                    obj_out = obj_out.get_mut(field_name).unwrap();
                }

                *obj_out = value.clone();
            }

            for field_name in ["filter", "filter_range", "filter_range_min", "filter_range_max", "aggregate", "instance", "sort"] {
                if obj_out.get(field_name).is_none() {
                    obj_out[field_name] = json!({});
                }
            }

            if obj_out.get("page").is_none() {
                obj_out["page"] = json!(1);
            }

            if obj_out.get("page_size").is_none() {
                obj_out["page_size"] = json!(25);
            }

            let params_search = serde_json::from_value::<DataViewParams>(obj_out.clone())?;
            Ok((params_search, obj_out))
        } else {
            Ok((DataViewParams::default(), json!({})))
        }
    }
    
    async fn process_click_target(&mut self, target: &str) -> Result<DataViewResponse, Box<dyn std::error::Error>> {
        let re = regex::Regex::new(r"create-((?P<parent_action>new|edit|view|search|filter|aggregate|sort)-(?P<parent_name>\pL[\w_]+)--)?(?P<action>new|edit|view|search|filter|aggregate|sort)-(?P<name>\pL[\w_]+)$")?;

        if let Some(cap) = re.captures(target) {
            let mut element_id = HtmlElementId::new_with_regex(&cap)?;
            element_id.data_view_id.set_action(DataViewProcessAction::New);
            let mut data_view_response = DataViewResponse::default();
            self.process_data_view_action(&element_id, &DataViewParams::default(), &json!({}), &mut data_view_response).await?;
            return Ok(data_view_response);
        }

        let re = regex::Regex::new(r"delete-((?P<parent_action>new|edit|view|search|filter|aggregate|sort)-(?P<parent_name>\pL[\w_]+)--)?(?P<action>new|edit|view|search|filter|aggregate|sort)-(?P<name>\pL[\w_]+)")?;

        if let Some(cap) = re.captures(target) {
            let mut element_id = HtmlElementId::new_with_regex(&cap)?;
            let data_view = data_view_get_mut!(self, element_id);

            let primary_key = data_view.params.primary_key.as_ref().ok_or_else(|| {
                format!("don't opened item in form_id {}", data_view.data_view_id.id)}
            )?.clone();

            self.server_connection.remove(&data_view.data_view_id.schema_name, &primary_key).await?;
            data_view.state.hidden = true;
            let mut data_view_response = DataViewResponse::default();
            data_view_response.forms.insert(data_view.data_view_id.id.clone(), data_view.state.clone());
            let params_search = DataViewParams { ..Default::default() };
            let params_extra = json!({});
            element_id.data_view_id.set_action(DataViewProcessAction::Search);
            let data_view = data_view_get_mut!(self, element_id);

            if let Some(pos) = data_view.filter_results.iter().position(|item| crate::data_store::Filter::check_match_exact(item, &primary_key).unwrap()) {
                data_view.filter_results.remove(pos);
            }

            self.process_data_view_action(&element_id, &params_search, &params_extra, &mut data_view_response).await?;
            return Ok(data_view_response);
        }

        let re = regex::Regex::new(r"apply-((?P<parent_action>new|edit|view|search|filter|aggregate|sort)-(?P<parent_name>\pL[\w_]+)--)?(?P<action>new|edit|view|search|filter|aggregate|sort)-(?P<name>\pL[\w_\d/]+)$")?;

        if let Some(cap) = re.captures(target) {
            let mut element_id = HtmlElementId::new_with_regex(&cap)?;

            let data_view_response = match &element_id.data_view_id.action {
                DataViewProcessAction::Filter => {
                    let data_view = data_view_get!(self, element_id);
                    let params_search = data_view.params.clone();
                    element_id.data_view_id.set_action(DataViewProcessAction::Search);
                    let mut data_view_response = DataViewResponse::default();
                    self.process_data_view_action(&element_id, &params_search, &json!({}), &mut data_view_response).await?;
                    data_view_response
                }
                DataViewProcessAction::Aggregate => {
                    let data_view = data_view_get_mut!(self, element_id);
                    let aggregate = data_view.params.aggregate.clone();
                    data_view.apply_aggregate(&self.server_connection, &aggregate)?;
                    let mut data_view_response = DataViewResponse::default();
                    data_view_response.aggregates[&data_view.data_view_id.id] = json!(data_view.aggregate_results);
                    data_view_response
                }
                DataViewProcessAction::Sort => {todo!()}
                _ => {
                    let data_view = data_view_get_parent_mut!(self, element_id);
                    let (is_ok, action) = self.watcher.check_save(data_view, &element_id, &self.server_connection)?;

                    if is_ok {
                        let obj_in = data_view.save(&mut self.server_connection).await?;
                        let data_view = data_view_get_mut!(self, element_id);

                        let params_extra = if element_id.data_view_id.parent_schema_name.is_some() {
                            if data_view.path.is_some() {
                                data_view.save(&mut self.server_connection).await?
                            } else {
                                json!({})
                            }
                        } else {
                            obj_in                            
                        };

                        if data_view.typ == DataViewType::ObjectProperty {
                            if let Some(index) = data_view.active_index {
                                data_view.filter_results[index] = params_extra.clone();
                            }
                        } else {
                            data_view.state.hidden = true;
                        }

                        let mut data_view_response = DataViewResponse::default();
                        data_view.clear(&self.server_connection, &self.watcher)?;
                        data_view.build_changes(&mut data_view_response.changes)?;
                        data_view_response.forms.insert(element_id.data_view_id.id.clone(), data_view.state.clone());
                        element_id.data_view_id.set_action(action);
                        let params_search = DataViewParams::default();
                        self.process_data_view_action(&element_id, &params_search, &params_extra, &mut data_view_response).await?;
                        data_view_response
                    } else {
                        DataViewResponse::default()
                    }
                }
            };

            return Ok(data_view_response);
        }

        let re = regex::Regex::new(r"(table_row)-(?P<action_exec>new|edit|view|search)-((?P<parent_action>new|edit|view|search|filter|aggregate|sort)-(?P<parent_name>\pL[\w_]+)--)?(?P<action>new|edit|view|search|filter|aggregate|sort)-(?P<name>\pL[\w_]+)-(-(?P<field_name>\pL[\w_]+))?(-(?P<index>\d+))?")?;

        if let Some(cap) = re.captures(target) {
            let mut element_id = HtmlElementId::new_with_regex(&cap)?;
            let data_view = data_view_get_mut!(self, element_id);

            let data_view = if let Some(field_name) = element_id.field_name.as_ref() {
                data_view.childs.iter_mut().find(|data_view| &data_view.data_view_id.schema_name == field_name).ok_or_else(|| {
                    format!("Missing item 1 {} in {}", field_name, data_view.data_view_id.id)
                })?
            } else {
                data_view
            };

            let params_extra = if let Some(active_index) = element_id.index {
                let schema_name = &data_view.data_view_id.schema_name;

                let list = if data_view.path.is_none() || data_view.filter_results.len() > 0 {
                    &data_view.filter_results
                } else {
                    let service = self.server_connection.service_map.get(schema_name).ok_or_else(|| format!("2 - service_map : missing {}.", schema_name))?;
                    &service.list
                };
        
                data_view.active_index = Some(active_index);
                list.get(active_index).ok_or_else(|| format!("Missing {}.filter_results[{}], size = {}", schema_name, active_index, list.len()))?.clone()
            } else {
                data_view.params.instance.clone()
            };

            let params_search = DataViewParams { ..Default::default() };
            element_id.data_view_id.set_action(DataViewProcessAction::from(cap.name("action_exec").ok_or("broken action_exec")?.as_str()));
            let mut data_view_response = DataViewResponse::default();
            #[cfg(debug_assertions)]
            println!("{target}:\nelement_id = {:?}\nparams_search = {:?}\nparams_extra: {params_extra}", element_id, params_search);
            self.process_data_view_action(&element_id, &params_search, &params_extra, &mut data_view_response).await?;
            return Ok(data_view_response);
        }

        let re = regex::Regex::new(r"(?P<act>sort_left|sort_toggle|sort_rigth)-((?P<parent_action>new|edit|view|search|filter|aggregate|sort)-(?P<parent_name>\pL[\w_]+)--)?(?P<action>new|edit|view|search|filter|aggregate|sort)-(?P<name>\pL[\w_]+)--(?P<field_name>\pL[\w_]+)")?;

        if let Some(cap) = re.captures(target) {
            let element_id = HtmlElementId::new_with_regex(&cap)?;
            let data_view = data_view_get_mut!(self, element_id);
            let field_name = element_id.field_name.as_ref().ok_or_else(|| format!("broken field_name"))?;
            let field = data_view.params.sort.get_mut(field_name).ok_or_else(|| format!("Missing field sort : {}", field_name))?;

            match cap.name("act").ok_or_else(|| format!("broken"))?.as_str() {
                "sort_left" => field.order_index -= 1,
                "sort_rigth" => field.order_index += 1,
                _ => {
                    field.sort_type = if field.sort_type == FieldSortType::Asc { FieldSortType::Desc } else { FieldSortType::Asc };
                }
            }

            if data_view.filter_results.is_empty() {
                let service = self.server_connection.service_map.get(&data_view.data_view_id.schema_name).ok_or_else(|| format!("Missing service in service_map"))?;
                data_view.filter_results = service.list.clone();
            }

            data_view.apply_sort()?;
            let params_search = DataViewParams { ..Default::default() };
            let mut data_view_response = DataViewResponse::default();
            data_view_response.tables = json!({});
            let table = DataView::build_table(&self.server_connection, data_view, &params_search)?;
            data_view_response.tables[&data_view.data_view_id.id] = json!(table);
            return Ok(data_view_response);
        }

        let re = regex::Regex::new(r"selected_page-((?P<parent_action>new|edit|view|search|filter|aggregate|sort)-(?P<parent_name>\pL[\w_]+)--)?(?P<action>new|edit|view|search|filter|aggregate|sort)-(?P<name>\pL[\w_]+)--(?P<index>\d+)")?;

        if let Some(cap) = re.captures(target) {
            let element_id = HtmlElementId::new_with_regex(&cap)?;
            let data_view = data_view_get_mut!(self, element_id);
            data_view.params.page = element_id.index.ok_or_else(|| format!("broken index"))?;
            let params_search = DataViewParams { ..Default::default() };
            let mut data_view_response = DataViewResponse::default();
            data_view_response.tables = json!({});
            let table = DataView::build_table(&self.server_connection, data_view, &params_search)?;
            data_view_response.tables[&data_view.data_view_id.id] = json!(table);
            return Ok(data_view_response);
        }

        let re = regex::Regex::new(r"cancel-((?P<parent_action>new|edit|view|search|filter|aggregate|sort)-(?P<parent_name>\pL[\w_]+)--)?(?P<action>new|edit|view|search|filter|aggregate|sort)-(?P<name>\pL[\w_\d/]+)$")?;

        if let Some(cap) = re.captures(target) {
            let element_id = HtmlElementId::new_with_regex(&cap)?;
            let mut data_view_response = DataViewResponse::default();
            let data_view = data_view_get_mut!(self, element_id);
            data_view.clear(&self.server_connection, &self.watcher)?;
            data_view.build_changes(&mut data_view_response.changes)?;
            data_view.state.hidden = true;
            data_view_response.forms.insert(element_id.data_view_id.id.clone(), data_view.state.clone());
            return Ok(data_view_response);
        }

        let re = regex::Regex::new(r"(reference|search_select)-((?P<parent_action>new|edit|view|search|filter|aggregate|sort)-(?P<parent_name>\pL[\w_]+)--)?(?P<action>new|edit|view|search|filter|aggregate|sort)-(?P<name>\pL[\w_]+)-(-(?P<field_name>\pL[\w_]+))?(-(?P<index>\d+))?")?;

        let target = if let Some(cap) = re.captures(target) {
            let element_id = HtmlElementId::new_with_regex(&cap)?;
            let data_view = data_view_get!(self, element_id);

            if let Some(origin) = &data_view.params.origin {
                let obj = {
                    let index = element_id.index.ok_or_else(|| format!("Missing index"))?;

                    let list = if data_view.path.is_none() || data_view.filter_results.len() > 0 {
                        &data_view.filter_results
                    } else {
                        let schema_name = &data_view.data_view_id.schema_name;
                        let service = self.server_connection.service_map.get(schema_name).ok_or_else(|| format!("1 - service_map : missing {}.", schema_name))?;
                        &service.list
                    };
            
                    list.get(index).ok_or_else(|| format!("List broken of index"))?    
                };

                let re = regex::Regex::new(r"(?P<form_type>instance|filter|aggregate|sort)--((?P<parent_name>\pL[\w_]+)-)?(?P<name>\pL[\w_]+)--(?P<field_name>\pL[\w_]+)(?P<form_type_ext>@min|@max)?(-(?P<index>\d+))?")?;
                let cap = re.captures(origin).ok_or_else(|| format!("broken origin"))?;
                let element_id_origin = &HtmlElementId::new_with_regex(&cap)?;
                let field_name = element_id_origin.field_name.as_ref().ok_or_else(|| format!("missing field_name"))?;
                let data_view_origin = data_view_get!(self, element_id_origin);               
                let (_, foreign_key) = self.server_connection.login_response.openapi.get_foreign_key(&data_view_origin.properties, &data_view_origin.extensions, field_name, obj)?.ok_or_else(|| format!("Missing foreign value."))?;
                let value = foreign_key.get(field_name).ok_or_else(|| format!("Missing field"))?;
                let data_view_origin = data_view_get_parent_mut!(self, element_id_origin);
                data_view_origin.set_value(&self.server_connection, self.watcher.as_ref(), field_name, &value, Some(element_id_origin))?;
                let mut data_view_response = DataViewResponse::default();
                data_view_origin.build_changes(&mut data_view_response.changes)?;
                data_view_origin.state.hidden = true;
                data_view_response.forms.insert(element_id.data_view_id.id.clone(), data_view_origin.state.clone());
                return Ok(data_view_response);
            }

            let href_go_to_field = data_view.build_go_to_field(&self.server_connection, &element_id, &element_id.data_view_id.action, &data_view.params.instance)?;
            href_go_to_field.unwrap_or("#".to_string())
        } else {
            target.to_string()
        };

        let re = regex::Regex::new(r"((?P<parent_action>new|edit|view|search|filter|aggregate|sort)-(?P<parent_name>\pL[\w_]+)--)?(?P<action>new|edit|view|search|filter|aggregate|sort)-(?P<name>\pL[\w_\d/]+)--(?P<field_name>\pL[\w_]+)(?P<form_type_ext>@min|@max)?(-(?P<index>\d+))?")?;

        if let Some(cap) = re.captures(&target) {
            let element_id = &HtmlElementId::new_with_regex(&cap)?;
            // TODO : check if dataview is "visible" and "enabled"
            let data_view = data_view_get!(self, element_id);
            // TODO : check if field is "visible" and "enabled"
            let field_name = element_id.field_name.as_ref().ok_or_else(|| format!("missing field_name"))?;
            let value = data_view.get_form_type_instance(&element_id.data_view_id.action, &element_id.form_type_ext)?.get(field_name).unwrap_or(&Value::Null);
        
            let field = data_view.properties.get(field_name).ok_or_else(|| {
                format!("set_value_process : missing field {} in data_view {}", field_name, data_view.data_view_id.id)
            })?;
    
            let field = field.as_item().ok_or_else(|| format!("[process_edit_target.parse_value({})] broken", value))?;
            let extensions = &field.schema_data.extensions;

            if let Some(_) = extensions.get("x-flags") {
                let index = element_id.index.ok_or_else(|| format!("Missing flag_index"))?;
                let field_value = data_view.get_form_type_instance(&element_id.data_view_id.action, &element_id.form_type_ext)?.get(field_name).unwrap_or(&Value::Null);

                let value = match field_value {
                    Value::Null => return Err(format!("Expected u64, found Null"))?,
                    Value::Bool(b) => return Err(format!("Expected u64, found Bool({b})"))?,
                    Value::Number(number) => number.as_u64().ok_or_else(|| format!("Is not u64"))?,
                    Value::String(s) => return Err(format!("Expected u64, found String({s})"))?,
                    Value::Array(values) => return Err(format!("Expected u64, found Array({:?})", values))?,
                    Value::Object(map) => return Err(format!("Expected u64, found Object({:?})", map))?,
                };

                let value = value & (1 << index);
                let value = value == 0;
                let value = value.to_string();
                return self.process_edit_target(&target, &value).await;
            }            

            let data_view_response = DataViewResponse::default();
            return Ok(data_view_response);
        }

        let re = regex::Regex::new(r"#!/app/((?P<parent_name>\pL[\w_]+)-)?(?P<name>\pL[\w_\.\d]+)/(?P<action>new|edit|view|search)(?P<query_string>\?[\w\.=&\-/]+)?")?;

        if let Some(cap) = re.captures(&target) {
            let element_id = HtmlElementId::new_with_regex(&cap)?;

            let (params_search, params_extra) = if let Some(query_string) = cap.name("query_string") {
                DataViewManager::parse_query_string(query_string.as_str())?
            } else {
                (DataViewParams::default(), json!({}))
            };

            let mut data_view_response = DataViewResponse::default();
            #[cfg(debug_assertions)]
            println!("{target}:\nelement_id = {:?}\nparams_search = {:?}\nparams_extra: {params_extra}", element_id, params_search);
            self.process_data_view_action(&element_id, &params_search, &params_extra, &mut data_view_response).await?;
            return Ok(data_view_response);
        }

        let re = regex::Regex::new(r"login-(?P<name>\pL[\w_]+)")?;
        
        if let Some(_cap) = re.captures(&target) {
            let data_view_response = DataViewResponse::default();
            return Ok(data_view_response);
        }

        let re = regex::Regex::new(r"menu-(?P<name>[\w_]+)")?;
        
        if let Some(_cap) = re.captures(&target) {
            let data_view_response = DataViewResponse::default();
            return Ok(data_view_response);
        }

        None.ok_or_else(|| format!("unknow click taget"))?
    }

    async fn process_edit_target(&mut self, target: &str, value: &str) -> Result<DataViewResponse, Box<dyn std::error::Error>> {
        fn parse_value_process(data_view: &DataView, server_connection: &ServerConnection, element_id: &HtmlElementId, value: &str) -> Result<(Value, bool), Box<dyn std::error::Error>> {
            //data_view.field_external_references_str.insert(field_name.to_string(), value.to_string());
            let Some(field_name) = &element_id.field_name else {
                return None.ok_or_else(|| format!("[process_edit_target] missing field field_name"))?;
            };

            let field = data_view.properties.get(field_name).ok_or_else(|| {
                format!("[process_edit_target.parse_value()] Missing field {}.{}", data_view.data_view_id.schema_name, field_name)
            })?;

            let field = field.as_item().ok_or_else(|| format!("[process_edit_target.parse_value({})] broken", value))?;
            let extensions = &field.schema_data.extensions;
            let mut is_flags = false;

            let value = if let Some(_) = extensions.get("x-flags") {
                let index = element_id.index.ok_or_else(|| format!("Missing flag_index"))?;
                let field_value = data_view.get_form_type_instance(&element_id.data_view_id.action, &element_id.form_type_ext)?.get(field_name).unwrap_or(&Value::Null);

                let field_value = match field_value {
                    Value::Null => return Err(format!("Expected u64, found Null"))?,
                    Value::Bool(b) => return Err(format!("Expected u64, found Bool({b})"))?,
                    Value::Number(number) => number.as_u64().ok_or_else(|| format!("Is not u64"))?,
                    Value::String(s) => return Err(format!("Expected u64, found String({s})"))?,
                    Value::Array(values) => return Err(format!("Expected u64, found Array({:?})", values))?,
                    Value::Object(map) => return Err(format!("Expected u64, found Object({:?})", map))?,
                };

                let bit_mask = if ["true", "on"].contains(&value) {
                    field_value | (1 << index)
                } else {
                    field_value & !(1 << index)
                };

                is_flags = true;
                json!(bit_mask)
            } else if let Some(_reference) = extensions.get("x-$ref") {
                if value.len() > 0 {
                    let field_results = data_view.field_results.get(field_name).ok_or_else(|| format!("Missing field_results"))?;
                    let field_results_str = data_view.field_results_str.get(field_name).ok_or_else(|| format!("value not found in field_results_str"))?;
                    let pos = field_results_str
                        .iter()
                        .position(|s| s.as_str() == value)
                        .ok_or_else(|| format!("(x-$ref) Missing foreign description {} in {}.", value, field_name))?;
                    let foreign_data = field_results.get(pos).ok_or_else(|| format!("broken 1 in parse_value"))?;
                    let (_, foreign_key) = server_connection
                        .login_response
                        .openapi
                        .get_foreign_key(&data_view.properties, &data_view.extensions, field_name, foreign_data)
                        .unwrap()
                        .unwrap();
                    foreign_key.get(field_name).ok_or_else(|| format!("broken 1 in parse_value"))?.clone()
                } else {
                    Value::Null
                }
            } else if let Some(enumeration) = extensions.get("x-enum") {
                let enumeration = enumeration.as_array().ok_or_else(|| format!("is not array"))?;

                if let Some(enum_labels) = extensions.get("x-enumLabels") {
                    let enum_labels = enum_labels.as_array().ok_or_else(|| format!("is not array"))?;
                    let pos = enum_labels
                        .iter()
                        .position(|item| {
                            if let Some(enum_label) = item.as_str() {
                                if enum_label == value {
                                    true
                                } else {
                                    false
                                }
                            } else {
                                false
                            }
                        })
                        .ok_or_else(|| format!("(x-enum) Missing foreign description {} in {}.", value, field_name))?;

                    enumeration.get(pos).ok_or_else(|| format!("expected value at pos"))?.clone()
                } else {
                    json!(value)
                }
            } else {
                json!(value)
            };

            Ok((value, is_flags))
        }

        let mut data_view_response = DataViewResponse::default();
        let re = regex::Regex::new(r"((?P<parent_action>new|edit|view|search|filter|aggregate|sort)-(?P<parent_name>\pL[\w_]+)--)?(?P<action>new|edit|view|search|filter|aggregate|sort)-(?P<name>\pL[\w_\d/]+)--(?P<field_name>\pL[\w_]+)(?P<form_type_ext>@min|@max)?(-(?P<index>\d+))?")?;

        if let Some(cap) = re.captures(target) {
            let element_id = &HtmlElementId::new_with_regex(&cap)?;
            let field_name = element_id.field_name.as_ref().ok_or_else(|| format!("missing field_name"))?;
            let data_view = data_view_get!(self, element_id);
            let (value, is_flags) = parse_value_process(data_view, &self.server_connection, element_id, value)?;
            let data_view_parent = data_view_get_parent_mut!(self, element_id);
            data_view_parent.set_value(&self.server_connection, self.watcher.as_ref(), field_name, &value, Some(element_id))?;
            data_view_parent.build_changes(&mut data_view_response.changes)?;

            if is_flags {
                let data_view = data_view_get_mut!(self, element_id);
                let params_search = DataViewParams::default();
                let table = DataView::build_table(&self.server_connection, data_view, &params_search)?;
                data_view_response.tables[&data_view.data_view_id.id] = json!(table);
            }

            return Ok(data_view_response);
        }

        let re = regex::Regex::new(r"login-(?P<name>\pL[\w_]+)")?;

        for cap in re.captures_iter(target) {
            let name = cap.name("name").unwrap().as_str();

            if ["user", "password", "customer_id"].contains(&name) {
                return Ok(data_view_response);
            }
        }

        None.ok_or_else(|| format!("unknow edit taget"))?
    }

    pub async fn process(&mut self, params: Value) -> Result<Value, Box<dyn std::error::Error>> {
        #[cfg(debug_assertions)]
        println!("Request:\n{}", params);

        #[derive(Deserialize)]
        struct EventIn {
            form_id: String,
            event: String,
            data: Value,
        }

        let params = serde_json::from_value::<EventIn>(params)?;

        let data_view_response = if params.event == "OnClick" {
            self.process_click_target(&params.form_id).await?
        } else {
            let mut ret = DataViewResponse::default();

            for (target, value) in params.data.as_object().ok_or_else(|| format!("Param 'data' is not object "))? {
                ret = self.process_edit_target(target, value.as_str().ok_or_else(|| format!("not string"))?).await?;
            }

            ret
        };

        let res = serde_json::to_value(data_view_response)?;
        Ok(res)
    }
}

#[cfg(target_arch = "wasm32")]
use wasm_bindgen::prelude::*;

use crate::openapi::{Dependent, Role, RufsOpenAPI, SchemaExtensions, SchemaPlace, SchemaProperties};

#[cfg(target_arch = "wasm32")]
pub struct DataViewManagerWrapper<'a> {
    pub data_view_manager: DataViewManager<'a>,
}

#[cfg(target_arch = "wasm32")]
impl DataViewManagerWrapper<'_> {
    pub async fn login_from_response(&mut self, params :JsValue) -> Result<JsValue, JsValue> {
        let params = serde_wasm_bindgen::from_value::<Value>(params)?;

        let ret = match self.data_view_manager.login_from_response(params).await {
            Ok(ret) => ret,
            Err(err) => return Err(JsValue::from_str(&err.to_string())),
        };

        Ok(serde_wasm_bindgen::to_value(&ret)?)
    }

    pub async fn process(&mut self, params: JsValue) -> Result<JsValue, JsValue> {
        let params = serde_wasm_bindgen::from_value::<Value>(params)?;

        let ret = match self.data_view_manager.process(params).await {
            Ok(ret) => ret,
            Err(err) => return Err(JsValue::from_str(&err.to_string())),
        };

        Ok(serde_wasm_bindgen::to_value(&ret)?)
    }
}

#[cfg(not(target_arch = "wasm32"))]
#[cfg(feature = "test-selelium")]
pub mod tests {
    use convert_case::Casing;
    use serde::Deserialize;
    use serde_json::{json, Value};
    use std::fs;

    use crate::{client::{DataViewManager, ServerConnection, HtmlElementId, DataViewParams}, data_store::Filter};

    use super::DataViewWatch;
    /*
        fn pause() {
            let mut stdin = io::stdin();
            let mut stdout = io::stdout();
            // We want the cursor to stay at the end of the line, so we print without a newline and flush manually.
            write!(stdout, "Press any key to continue...").unwrap();
            stdout.flush().unwrap();
            // Read a single byte and discard
            let _ = stdin.read(&mut [0u8]).unwrap();
        }
    */
    #[derive(Debug, Default, Deserialize)]
    struct SeleniumCommand {
        //id: String,
        //comment: String,
        command: String,
        target: String,
        //targets: Vec<Vec<String>>,
        value: String,
    }

    #[derive(Debug, Default, serde::Serialize)]
    struct StepWithSelectors {
        #[serde(rename="type")]
        typ: String,
        target: String,
        selectors: Vec<String>,
        url: Option<String>,
        value: Option<String>,
        visible: Option<bool>,
        count: Option<usize>,
        attributes: Option<Value>,
        properties: Option<Value>,
    }

    #[derive(Debug, Default, Deserialize)]
    struct SeleniumTest {
        id: String,
        name: String,
        commands: Vec<SeleniumCommand>,
    }

    #[derive(Debug, Default, serde::Serialize)]
    struct UserFlow {
        title: String,
        steps: Vec<StepWithSelectors>,
    }

    #[derive(Debug, Default, Deserialize)]
    struct SeleniumSuite {
        //id: String,
        name: String,
        //parallel: bool,
        //timeout: usize,
        tests: Vec<String>,
    }

    #[derive(Debug, Default, Deserialize)]
    struct SeleniumIde {
        //id: String,
        //version: String,
        name: String,
        //url: String,
        tests: Vec<SeleniumTest>,
        suites: Vec<SeleniumSuite>,
        //urls: Vec<String>,
        //plugins: Vec<String>,
    }

    pub async fn selelium(watcher: &'static Box<dyn DataViewWatch>, side_file_name: &str, server_url: &str) -> Result<(), Box<dyn std::error::Error>> {
        #[async_recursion::async_recursion]
        async fn test_run(data_view_manager: &mut DataViewManager, side_file_name: &str, side: &SeleniumIde, suite: &SeleniumSuite, id_or_name: &str) -> Result<(), Box<dyn std::error::Error>> {
            if let Some(test) = side.tests.iter().find(|test| test.id == id_or_name || test.name == id_or_name) {
                println!("\nRunning test {}...", test.name);
                let mut user_flow = UserFlow{title: test.name.clone(), ..Default::default()};

                for command in &test.commands {
                    if command.command.as_str().starts_with("//") {
                        continue;
                    }

                    let mut puppeteer_step = StepWithSelectors::default();
                    let mut target = command.target.clone();
                    println!("\nRunning command {} in target {} with value {}...", command.command.as_str(), target, command.value);

                    match command.command.as_str() {
                        "open" => {
                            let url = "http://localhost:8080";
                            data_view_manager.data_view_map.clear();
                            data_view_manager.server_connection = ServerConnection::new(url);
                            puppeteer_step.typ = "navigate".to_string();
                            puppeteer_step.url = Some(url.to_string());
                        }
                        "run" => {
                            test_run(data_view_manager, side_file_name, side, suite, &command.target).await?;
                            continue;
                        }
                        "click" | "clickAt" => {
                            match command.target.as_str() {
                                "id=login-send" => {
                                    if let Some(customer_id) = test
                                        .commands
                                        .iter()
                                        .find(|command| ["type", "sendKeys"].contains(&command.command.as_str()) && command.target == "id=login-customer_id")
                                    {
                                        if let Some(user) = test
                                            .commands
                                            .iter()
                                            .find(|command| ["type", "sendKeys"].contains(&command.command.as_str()) && command.target == "id=login-user")
                                        {
                                            if let Some(password) = test
                                                .commands
                                                .iter()
                                                .find(|command| ["type", "sendKeys"].contains(&command.command.as_str()) && command.target == "id=login-password")
                                            {
                                                let customer_user = format!("{}.{}", customer_id.value, user.value);
                                                //let password = md5::compute(password);
                                                //let password = format!("{:x}", password);
                                                match data_view_manager.server_connection.login("/login", &customer_user, &password.value).await {
                                                    Ok(_) => target = format!("#!/app/{}", data_view_manager.server_connection.login_response.path),
                                                    Err(err) => {
                                                        if let Some(http_msg) = test.commands.iter().find(|command| command.command == "assertText" && command.target == "id=http-error") {
                                                            if err.to_string().ends_with(&http_msg.value) {
                                                                break;
                                                            } else {
                                                                println!("received : {}", err);
                                                                println!("expected : {}", http_msg.value);
                                                            }
                                                        }

                                                        let res = Err(err);
                                                        return res?;
                                                    }
                                                }
                                            }
                                        }
                                    }
                                },
                                _ => {}
                            }

                            puppeteer_step.typ = command.command.clone();
                            let _res = data_view_manager.process_click_target(&target).await?;
                        }
                        "type" | "sendKeys" | "select" => {
                            let value = if command.value.starts_with("label=") { &command.value[6..] } else { &command.value };
                            let re = regex::Regex::new(r"(?P<day>\d{2})(?P<month>\d{2})(?P<year>\d{4})\$\{KEY_TAB\}(?P<hour>\d{2})(?P<minute>\d{2})")?;
                            let value = re.replace(value, "${year}-${month}-${day}T${hour}:${minute}");
                            puppeteer_step.typ = "change".to_string();
                            puppeteer_step.value = Some(value.to_string());
                            let _res = data_view_manager.process_edit_target(&command.target, &value).await?;
                        }
                        "assertText" | "assertValue" | "assertSelectedValue" => {
                            let re = regex::Regex::new(r"id=(?P<name>\pL[\w_]+)")?;

                            if let Some(cap) = re.captures(&command.target) {
                                let name = cap.name("name").unwrap().as_str();

                                match name {
                                    "http-error" => {}
                                    _ => {}
                                }
                            }

                            let re = regex::Regex::new(r"((?P<parent_action>new|edit|view|search|filter|aggregate|sort)-(?P<parent_name>\pL[\w_]+)--)?(?P<action>new|edit|view|search|filter|aggregate|sort)-(?P<name>\pL[\w_\d/]+)--(?P<field_name>\pL[\w_]+)(?P<form_type_ext>@min|@max)?(-(?P<index>\d+))?")?;

                            let Some(cap) = re.captures(&target) else {
                                println!("\nDon't match target !\n");
                                continue;
                            };

                            let element_id = HtmlElementId::new_with_regex(&cap)?;
                            let field_name = cap.name("field_name").unwrap().as_str();

                            let data_view = data_view_get_mut!(data_view_manager, element_id);

                            let str = if let Some(index) = cap.name("index") {
                                let list = if data_view.path.is_none() || data_view.filter_results.len() > 0 {
                                    &data_view.filter_results
                                } else {
                                    let service = data_view_manager
                                        .server_connection
                                        .service_map
                                        .get(&data_view.data_view_id.schema_name)
                                        .ok_or_else(|| format!("Missing service in service_map"))?;
                                    &service.list
                                };

                                let index = index.as_str().parse::<usize>()?;
                                let value = list.get(index).ok_or_else(|| format!("Don't found value of index {}", index))?;
                                value
                                    .get(field_name)
                                    .ok_or_else(|| format!(
                                        "[{}] target = {} : Don't found field {}, json = {}",
                                        command.command.as_str(),
                                        target,
                                        field_name,
                                        value
                                    ))?
                                    .to_string()
                            } else if let Some(str) = data_view.field_external_references_str.get(field_name) {
                                str.clone()
                            } else if let Some(value) = data_view.params.instance.get(field_name) {
                                match value {
                                    Value::String(value) => value.to_string(),
                                    Value::Bool(value) => value.to_string(),
                                    Value::Null => "".to_string(),
                                    Value::Number(value) => value.to_string(),
                                    Value::Array(_) => todo!(),
                                    Value::Object(_) => todo!(),
                                }
                            } else {
                                "".to_string()
                            };

                            let re = regex::Regex::new(r"(?P<year>\d{4})-(?P<month>\d{2})-(?P<day>\d{2})T(?P<hour>\d{2}):(?P<minute>\d{2}):(?P<second>\d{2})")?;
                            let str = re.replace(&str, "${year}-${month}-${day}T${hour}:${minute}");

                            let value = if command.value.starts_with("string:") { &command.value[7..] } else { &command.value };

                            if value != &str {
                                let field_value = data_view.get_form_type_instance(&element_id.data_view_id.action, &element_id.form_type_ext)?.get(field_name).unwrap_or(&Value::Null).to_string();
                                let empty_list = vec![];
                                let options = data_view.field_results_str.get(field_name).unwrap_or(&empty_list).join("\n");
                                return Err(format!(
                                    "[{}({})] : In schema {}, field {}, value of instance ({}) don't match with expected ({}).\nfield_value = {field_value}\nfield_results_str:\n{}",
                                    command.command.as_str(),
                                    target,
                                    target,
                                    field_name,
                                    str,
                                    value,
                                    options
                                ))?;
                            }

                            puppeteer_step.typ = "waitForElement".to_string();
                            puppeteer_step.attributes = Some(json!({"value": str}));
                        }
                        "assertElementNotPresent" => {
                            let re = regex::Regex::new(r"#!/app/((?P<parent_name>\pL[\w_]+)-)?(?P<name>\pL[\w_]+)/(?P<action>\w+)(?P<query_string>\?[^']+)?")?;

                            if let Some(cap) = re.captures(&target) {
                                let element_id = HtmlElementId::new_with_regex(&cap)?;

                                let (params_search, params_extra) = if let Some(query_string) = cap.name("query_string") {
                                    DataViewManager::parse_query_string(query_string.as_str())?
                                } else {
                                    (DataViewParams::default(), json!({}))
                                };
                    
                                let primary_key = if let Some(primary_key) = &params_search.primary_key { primary_key } else { &params_extra };
                                let data_view = data_view_get!(data_view_manager, element_id);

                                let is_broken = if data_view.path.is_some() {
                                    let service = data_view_manager
                                        .server_connection
                                        .service_map
                                        .get(&data_view.data_view_id.schema_name)
                                        .ok_or_else(|| format!("Missing service {}", &data_view.data_view_id.schema_name))?;

                                    if let Some(value) = service.find_pos(primary_key)? {
                                        println!("Unexpected existence of item in service.list : pos = {}", value);
                                        true
                                    } else {
                                        false
                                    }
                                } else {
                                    false
                                };

                                if let Some(index) = Filter::find_index(&data_view.filter_results, primary_key).unwrap() {
                                    println!("Unexpected existence of item of index {} in filter_results.", index);
                                } else if !is_broken {
                                    continue;
                                }
                            }

                            puppeteer_step.typ = "waitForElement".to_string();
                            puppeteer_step.count = Some(0);
                        }
                        "waitForElementNotVisible" => {
                            // <button id="cancel-{form_id}" name="cancel" class="btn btn-default"><i class="bi bi-exit"></i> Fechar</button>
                            // "target": "id=(cancel|delete|clear|apply)-(new|view)-person"
                            puppeteer_step.typ = "waitForElement".to_string();
                            puppeteer_step.visible = Some(false);
                        }
                        "waitForElementVisible" => {
                            puppeteer_step.typ = "waitForElement".to_string();
                            puppeteer_step.visible = Some(true);
                        }
                        _ => {}
                    }

                    puppeteer_step.selectors.push(target);
                    user_flow.steps.push(puppeteer_step);
                }

                {
                    let path = std::path::PathBuf::from(side_file_name);
                    let parent = path.parent().ok_or("Broken on get side parent.")?;
                    let dir_out = parent.join("puppeteer").join(&side.name.to_case(convert_case::Case::Snake)).join(suite.name.to_case(convert_case::Case::Snake));
                    std::fs::create_dir_all(&dir_out)?;
                    let path = dir_out.join(test.name.to_case(convert_case::Case::Snake) + ".json");
                    let contents = serde_json::to_string(&user_flow)?;
                    std::fs::write(path, &contents)?;
                }
        
                println!("... test {} is finalized with successfull !\n", test.name);
            }

            Ok(())
        }

        let mut data_view_manager = DataViewManager::new(server_url, watcher);
        let file = fs::File::open(side_file_name).expect("file should open read only");
        let side: SeleniumIde = serde_json::from_reader(file).expect("file should be proper JSON");

        for suite in &side.suites {
            println!("suite : {:?}", suite);

            for id in &suite.tests {
                test_run(&mut data_view_manager, side_file_name, &side, &suite, &id).await?
            }
        }

        Ok(())
    }
    /*
        #[test]
        fn login() {
            tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .start_paused(true)
            .build()
            .unwrap()
            .block_on(async {
                assert!(true);
            })

        }
    */
}
