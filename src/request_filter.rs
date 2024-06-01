use std::collections::HashMap;

use jsonwebtoken::{decode, DecodingKey, Validation};
use openapiv3::ReferenceOr;
use serde::{Serialize, Deserialize};
use serde_json::{json, Value};
use crate::openapi::{RufsOpenAPI, SchemaPlace, SchemaProperties};

#[cfg(not(target_arch = "wasm32"))]
use crate::{
    entity_manager::EntityManager,
    rufs_micro_service::{Claims, RufsMicroService},
};

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
struct NotifyMessage {
    service    :String,
    action     :String,
    primary_key :Value
}

#[cfg(not(target_arch = "wasm32"))]
#[cfg(feature = "http_server")]
pub struct RequestFilter<'a> {
    micro_service: &'a RufsMicroService<'a>,
    entity_manager: Option<Box<&'a (dyn EntityManager + Send + Sync)>>,
    token_payload: Option<Claims>,
    path: String,
    pub method: String,
    pub schema_name: String,
    parameters: Value,
    obj_in: Value,
    may_be_array: bool
}

#[cfg(not(target_arch = "wasm32"))]
#[cfg(feature = "http_server")]
impl<'a> RequestFilter<'a> {
    pub fn new<'b>(rms: &'b RufsMicroService<'b>, path: &'b str, query: Option<&'b str>, method: &'b str, obj_in: Value) -> Result<RequestFilter<'a>, Box<dyn std::error::Error>> where 'b: 'a {
        let mut rf = Self { micro_service: &rms, entity_manager: Default::default(), token_payload: Default::default(), path: Default::default(), method: Default::default(), schema_name: Default::default(), parameters: Default::default(), obj_in: Default::default(), may_be_array: false };
        rf.method = method.to_string();
        rf.obj_in = obj_in;

        if let Some(query) = query {
            rf.parameters = queryst::parse(query).unwrap();
            println!("[RequestFilter.new()] rf.parameters = {}", rf.parameters.to_string());
        }

        let rest_path = if let Some(pos) = path.find(&format!("/{}/", rms.params.api_path)) {
            &path[pos + 1 + rms.params.api_path.len()..]
        } else {
            path
        };

        rf.path = rms.openapi.get_path_params(rest_path, &rf.parameters).unwrap();

        rf.may_be_array = match &rf.parameters {
            Value::Object(obj) => !(obj.contains_key("id") || obj.contains_key("primaryKey")),
            _ => true,
        };

        rf.schema_name = rms.openapi.get_schema_name(&rf.path, &rf.method, false).unwrap();

        if rms.db_adapter_file.have_table(&rf.schema_name) {
            rf.entity_manager = Some(Box::new(&rms.db_adapter_file));
        } else {
            rf.entity_manager = Some(Box::new(&rms.entity_manager));
        }

        println!("[RequestFilter.new] : path = {}, method = {}, schema_name = {}, parameters = {}", rf.path, rf.method, rf.schema_name, rf.parameters);
        Ok(rf)
    }
    // private to create,update,delete,read
    fn check_object_access(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        let openapi = &self.micro_service.openapi;
        let user_rufs_group_owner = &self.token_payload.as_ref().unwrap().rufs_group_owner;
        //let rufs_group_owner_entries = openapi.get_properties_with_ref(&self.schema_name, "#/components/schemas/rufsGroupOwner");

        if user_rufs_group_owner == "admin" {
            return Ok(());
        }

        let obj = &mut self.obj_in;

        let mut obj_rufs_group_owner = if let Some(obj_rufs_group_owner) = openapi.get_primary_key_foreign(&self.schema_name, "rufsGroupOwner", obj)? {
            obj_rufs_group_owner
        } else {
            return Ok(());
        };

        if obj_rufs_group_owner.valid == false {
            obj["rufsGroupOwner"] = json!(user_rufs_group_owner);
            obj_rufs_group_owner.primary_key["name"] = json!(user_rufs_group_owner);
        }

        let obj_rufs_group_owner_id = obj_rufs_group_owner.primary_key.get("name").unwrap().as_str().unwrap().to_string();

        if &obj_rufs_group_owner_id == user_rufs_group_owner {
            if let Some(rufs_group) = openapi.get_primary_key_foreign(&self.schema_name, "rufsGroup", obj)? {
                let rufs_group_id = rufs_group.primary_key.get("name").unwrap().as_str().unwrap().to_string();
                let mut found = false;

                for group in self.token_payload.as_ref().unwrap().groups.as_ref().iter().as_ref() {
                    if *group == rufs_group_id {
                        found = true;
                        break;
                    }
                }

                if !found {
                    return Err("404-Unauthorized object rufsGroup.")?;
                }
            } else {
                return Ok(());
            }
        } else {
            return Err("404-Unauthorized object rufsGroupOwner.")?;
        }

        Err("Unknow")?
    }

    async fn process_create(&mut self) -> Result<Value, Box<dyn std::error::Error>> {
        self.check_object_access()?;
        let entity_manager = self.entity_manager.as_ref().unwrap();
        let openapi = &self.micro_service.openapi;
        let new_obj = entity_manager.insert(openapi, &self.schema_name, &self.obj_in.clone()).await?;
        Ok(new_obj)
    }

    async fn get_object(&self, use_document :bool) -> Result<Box<Value>, Box<dyn std::error::Error>> {
        let key = self.parse_query_parameters(false)?;
        println!("[RequestFilter.get_object({})] : {}", self.schema_name, key);
        let entity_manager = self.entity_manager.as_ref().unwrap();
        let openapi = &self.micro_service.openapi;
        let obj = entity_manager.find_one(openapi, &self.schema_name, &key).await?.ok_or_else(|| format!("Missing data in {} for key {}", self.schema_name, key))?;

        if use_document != true {
            return Ok(obj);
        }

        Err("[ResquestFilter.GetObject] don't implemented com rf useDocument == true")?
    }

    async fn process_read(&self) -> Result<Value, Box<dyn std::error::Error>> {
        println!("[RequestFilter.process_read({})]", self.schema_name);
        // TODO : check RequestBody schema
        let obj = self.get_object(false).await?.as_ref().clone();
        Ok(obj)
    }

    async fn process_update(&mut self) -> Result<Value, Box<dyn std::error::Error>> {
        //let obj = self.get_object(false).await?;
        self.check_object_access()?;
        let primary_key = &self.parse_query_parameters(false).unwrap();
        println!("[RequestFilter.process_update({})] : {}", self.schema_name, primary_key);
        let entity_manager = self.entity_manager.as_ref().unwrap();
        let new_obj = entity_manager.update(&self.micro_service.openapi, &self.schema_name, primary_key, &self.obj_in).await?;
        self.notify(&new_obj, false);
        Ok(new_obj)
    }

    async fn process_delete(&mut self) -> Result<Value, Box<dyn std::error::Error>> {
        let obj_deleted = self.get_object(false).await?;
        let primary_key = &self.parse_query_parameters(false).unwrap();
        let entity_manager = self.entity_manager.as_ref().unwrap();
        entity_manager.delete_one(&self.micro_service.openapi, &self.schema_name, primary_key).await?;
        self.notify(&obj_deleted, true);
        Ok(obj_deleted.as_ref().clone())
    }
/*
    func (rf *RequestFilter) processPatch() Response {
        return ResponseInternalServerError("TODO")
    }
*/
    fn parse_query_parameters(&self, ignore_null: bool) -> Result<Value, Box<dyn std::error::Error>> {
        let obj = self.micro_service.openapi.copy_fields(&self.path, &self.method, &SchemaPlace::Parameter, true, &self.parameters, ignore_null, false, false).unwrap();
        //println!("[openapi.parse_query_parameters({})] : {}", self.parameters, obj.to_string());
        Ok(obj)
    }

    async fn process_query(&self) -> Result<Value, Box<dyn std::error::Error>> {
        fn get_order_by(properties: &SchemaProperties) -> Vec<String> {
            let mut order_by = Vec::<String>::new();

            for (field_name, field) in properties {
                match field {
                    ReferenceOr::Item(schema) => match &schema.schema_kind {
                        openapiv3::SchemaKind::Type(typ) => match typ {
                            openapiv3::Type::Integer(_) => order_by.push(format!("{} desc", field_name)),
                            openapiv3::Type::String(x) => {
                                match &x.format {
                                    openapiv3::VariantOrUnknownOrEmpty::Item(format) => match format {
                                        openapiv3::StringFormat::Date => order_by.push(format!("{} desc", field_name)),
                                        openapiv3::StringFormat::DateTime => order_by.push(format!("{} desc", field_name)),
                                        _ => todo!(),
                                    },
                                    _ => order_by.push(field_name.to_string()),
                                };
                            },
                            _ => todo!(),
                        },
                        _ => todo!(),
                    },
                    ReferenceOr::Reference { reference: _ } => order_by.push(format!("{} desc", field_name)),
                }
            }

            order_by
        }

        let schema = self.micro_service.openapi.get_schema_from_parameters(&self.path, &self.method, true).unwrap();
        let fields = self.parse_query_parameters(true).unwrap();

        let order_by = match &schema.schema_kind {
            openapiv3::SchemaKind::Type(typ) => match typ {
                openapiv3::Type::Object(object_type) => get_order_by(&object_type.properties),
                _ => todo!(),
            },
            openapiv3::SchemaKind::Any(any) => get_order_by(&any.properties),
            _ => todo!(),
        };

        let list = self.entity_manager.as_ref().ok_or("Broken entity_manager.as_ref.")?.find(&self.micro_service.openapi, &self.schema_name, &fields, &order_by).await?;
        println!("[RequestFilter.process_query] : returning {} registers.", list.len());
        Ok(Value::Array(list))
    }

    pub async fn check_authorization<State>(&mut self, headers: &HashMap<String, String>) -> Result<bool, Box<dyn std::error::Error + Sync + Send>> {
        fn check_mask(mask: u64, method: &str) -> bool {
            let list = vec!["get", "post", "put", "patch", "delete", "query"];

            if let Some(idx) = list.iter().position(|&x| x == method) {
                (mask & (1 << idx)) != 0
            } else {
                false
            }
        }

        let openapi = &self.micro_service.openapi;

        for security_item in openapi.security.as_ref().ok_or("Missing openapi.security")? {
            for (security_name, _) in security_item {
                let Some(security_scheme) = openapi.components.as_ref().ok_or("Broken components")?.security_schemes.get(security_name) else {
                    continue;
                };

                let security_scheme = security_scheme.as_item().ok_or("Broken security_scheme.as_item()")?;

                match &security_scheme {
                    openapiv3::SecurityScheme::APIKey { location, name, description: _ } => match &location {
                        openapiv3::APIKeyLocation::Query => todo!(),
                        openapiv3::APIKeyLocation::Header => {
                            for (map_name, token_raw) in headers {
                                if map_name.as_str().to_lowercase() == name.to_lowercase() {
                                    if let Some(_user) = self.micro_service.db_adapter_file.find_one(openapi, "rufsUser", &json!({ "password": token_raw })).await.unwrap().take() {
                                        //let x = serde_json::from_value(user.clone()).unwrap();
                                        //self.token_payload = x;
                                    } else {
                                        return Ok(false);
                                    }

                                    break;
                                }
                            }
                        }
                        openapiv3::APIKeyLocation::Cookie => todo!(),
                    },
                    openapiv3::SecurityScheme::HTTP { scheme, bearer_format, description: _ } => {
                        if scheme == "bearer" && bearer_format.as_ref().ok_or("Broken bearer_format.as_ref()")? == "JWT" {
                            let authorization_header_prefix = "Bearer ";
                            let token_raw = headers.get(&"Authorization".to_lowercase()).ok_or("Missing header Authorization")?;

                            if token_raw.starts_with(authorization_header_prefix) {
                                let token_raw = &token_raw[authorization_header_prefix.len()..];
								let secret = std::env::var("RUFS_JWT_SECRET").unwrap_or("123456".to_string());
								let x = decode::<Claims>(&token_raw, &DecodingKey::from_secret(secret.as_ref()), &Validation::default()).unwrap();
								self.token_payload = Some(x.claims);
                            }
                        }
                    }
                    openapiv3::SecurityScheme::OAuth2 { flows: _, description: _ } => todo!(),
                    openapiv3::SecurityScheme::OpenIDConnect { open_id_connect_url: _, description: _ } => todo!(),
                }
            }
        }

        if let Some(role) = self.token_payload.as_ref().ok_or("Broken token_payload")?.roles.iter().find(|&x| x.path == self.path) {
            if check_mask(role.mask, &self.method) {
                Ok(true)
            } else {
                Ok(false)
            }
        } else {
            Err(format!("404-[RequestFilter.CheckAuthorization] missing service {}.{} in authorized roles", self.path, self.method))?
        }
    }

    pub async fn process_request(&mut self) -> Result<Value, Box<dyn std::error::Error>> {
        //let schema_response = self.micro_service.openapi.get_schema(&self.path, &self.method, "responseObject").unwrap();
        println!("[RequestFilter.process_request] : {} {}", self.path, self.method);

        if self.method == "get" {
            if self.may_be_array {
                return self.process_query().await
            } else {
                return self.process_read().await
            }
        } else if self.method == "post" {
                return self.process_create().await;
        } else if self.method == "put" {
            return self.process_update().await;
      /*} else if self.method == "patch" {
            resp = self.processPatch()*/
        } else if self.method == "delete" {
            return self.process_delete().await;
        } else {
            return Err(format!("400-[RequsetFilter.ProcessRequest] : unknow route for {}", self.path))?;
        }
    }

    fn notify(&self, obj :&Value, is_remove :bool) {
        let micro_service = self.micro_service;
        let openapi = &micro_service.openapi;
        let parameters = openapi.copy_fields(&self.path, &self.method, &SchemaPlace::Schemas, false, obj, false, false, true).unwrap();
        let mut msg = NotifyMessage{service: self.schema_name.to_string(), action: "notify".to_string(), primary_key: parameters};

        if is_remove {
            msg.action = "delete".to_string();
        }

        let msg = serde_json::to_string(&msg).unwrap();
        let obj_rufs_group_owner = openapi.get_primary_key_foreign(&self.schema_name, "rufsGroupOwner", obj).unwrap();
        let rufs_group = openapi.get_primary_key_foreign(&self.schema_name, "rufsGroup", obj).unwrap();
        println!("[RequestFilter.notify] broadcasting {:?} ...", msg);
        #[cfg(feature = "tide")]
        let map = micro_service.ws_server_connections_tide.read().unwrap();
        #[cfg(feature = "warp")]
        let mut map = micro_service.ws_server_connections_warp.write().unwrap();

        for (token_string, ws_server_connection) in map.iter_mut() {
            // enviar somente para os clients de "rufsGroupOwner"
            let key = &token_string.clone();
            let map = micro_service.ws_server_connections_tokens.read().unwrap();
            let token_data = map.get(key).unwrap();
            let mut check_rufs_group_owner = obj_rufs_group_owner.is_none();

            if check_rufs_group_owner == false {
                if let Some(name) = obj_rufs_group_owner.as_ref().unwrap().primary_key.get("name") {
                    if name.as_str().unwrap() == &token_data.rufs_group_owner {
                        check_rufs_group_owner = true;
                    }
                }
            }

            let mut check_rufs_group = rufs_group.is_none();

            if check_rufs_group == false {
                if let Some(name) = rufs_group.as_ref().unwrap().primary_key.get("name") {
                    if token_data.groups.contains(&name.as_str().unwrap().to_string()) {
                        check_rufs_group = true;
                    }
                }
            }
            // restrição de rufsGroup
            if token_data.rufs_group_owner == "admin" || (check_rufs_group_owner && check_rufs_group) {
                for role in token_data.roles.iter() {
                    if role.path == self.path {
                        if (role.mask & 0x01) != 0 {
                            println!("[RequestFilter.notify] send to client {}", token_data.name);
                            let rt = tokio::runtime::Runtime::new().unwrap();
                            #[cfg(feature = "tide")]
                            if let Err(error) = rt.block_on(ws_server_connection.send_string(msg.to_string())) {
                                println!("[RequestFilter.notify] send to client : {}", error);
                            }
                            #[cfg(feature = "warp")]
                            {
                                use futures_util::SinkExt;
                                use warp::ws::Message;

                                if let Err(error) = rt.block_on(ws_server_connection.send(Message::text(msg.to_string()))) {
                                    println!("[RequestFilter.notify] send to client : {}", error);
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    /*
    func RequestFilterUpdateRufsServices(entity_manager EntityManager, openapi *OpenApi) error {
        listDataStore := []*DataStore{}

        for name, schema := range openapi.Components.Schemas {
            listDataStore = append(listDataStore, &DataStore{name, schema})
        }

        return nil
    }
    */
}
