use anyhow::Context;
use indexmap::IndexMap;
use jsonwebtoken::{decode, DecodingKey, Validation};
use openapiv3::{ReferenceOr, Schema};
use serde::{Serialize, Deserialize};
use serde_json::{json, Value, Number};
use crate::openapi::{RufsOpenAPI, SchemaPlace};
#[cfg(not(target_arch = "wasm32"))]
#[cfg(feature = "tide")]
use tide::{Request, Error, StatusCode};

#[cfg(not(target_arch = "wasm32"))]
use crate::{
    entity_manager::{EntityManager},
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
#[cfg(feature = "tide")]
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
#[cfg(feature = "tide")]
impl<'a> RequestFilter<'a> {
    pub fn new<'b,  State>(req: &'b Request<State>, rms: &'b RufsMicroService<'b>, method: &'b str, obj_in: Value) -> Result<RequestFilter<'a>, tide::Error> where 'b: 'a {
        let mut rf = Self { micro_service: &rms, entity_manager: Default::default(), token_payload: Default::default(), path: Default::default(), method: Default::default(), schema_name: Default::default(), parameters: Default::default(), obj_in: Default::default(), may_be_array: false };
        rf.method = method.to_string();
        rf.obj_in = obj_in;

        if let Some(query) = req.url().query() {
            rf.parameters = queryst::parse(query).unwrap();
            println!("[RequestFilter.new()] rf.parameters = {}", rf.parameters.to_string());
        }

        let mut uri_path = req.url().path();

        if uri_path.starts_with(&format!("/{}/", rms.micro_service_server.api_path)) {
            uri_path = &uri_path[rms.micro_service_server.api_path.len() + 1..];
        }

        rf.path = rms.micro_service_server.openapi.get_path_params(uri_path, &rf.parameters).unwrap();

        rf.may_be_array = match &rf.parameters {
            Value::Object(obj) => !(obj.contains_key("id") || obj.contains_key("primaryKey")),
            _ => true,
        };

        rf.schema_name = rms.micro_service_server.openapi.get_schema_name(&rf.path, &rf.method, false).unwrap();

        if rms.db_adapter_file.have_table(&rf.schema_name) {
            rf.entity_manager = Some(Box::new(&rms.db_adapter_file));
        } else {
            rf.entity_manager = Some(Box::new(&rms.entity_manager));
        }

        println!("[RequestFilter.new] : path = {}, method = {}, schema_name = {}, parameters = {}", rf.path, rf.method, rf.schema_name, rf.parameters);
        Ok(rf)
    }
    // private to create,update,delete,read
    fn check_object_access(&mut self) -> Result<(), Error> {
        let openapi = &self.micro_service.micro_service_server.openapi;
        let user_rufs_group_owner = self.token_payload.as_ref().unwrap().rufs_group_owner;
        //let rufs_group_owner_entries = openapi.get_properties_with_ref(&self.schema_name, "#/components/schemas/rufsGroupOwner");

        if user_rufs_group_owner == 0 /*|| rufs_group_owner_entries.len() == 0*/ {
            return Ok(());
        }

        let obj = &mut self.obj_in;

        let mut obj_rufs_group_owner = if let Some(obj_rufs_group_owner) = openapi.get_primary_key_foreign(&self.schema_name, "rufsGroupOwner", obj).or(Err(Error::from_str(500, "unknow")))? {
            obj_rufs_group_owner
        } else {
            return Ok(());
        };

        if obj_rufs_group_owner.valid == false {
            obj["rufsGroupOwner"] = Value::Number(Number::from(user_rufs_group_owner));
            obj_rufs_group_owner.primary_key["id"] = Value::Number(Number::from(user_rufs_group_owner));
        }

        let obj_rufs_group_owner_id = obj_rufs_group_owner.primary_key.get("id").unwrap().as_u64().unwrap();

        if obj_rufs_group_owner_id == user_rufs_group_owner || user_rufs_group_owner == 1 {
            if let Some(rufs_group) = openapi.get_primary_key_foreign(&self.schema_name, "rufsGroup", obj)? {
                let rufs_group_id = rufs_group.primary_key.get("id").unwrap().as_u64().unwrap();
                let mut found = false;

                for group in self.token_payload.as_ref().unwrap().groups.as_ref().iter().as_ref() {
                    if *group == rufs_group_id {
                        found = true;
                        break;
                    }
                }

                if !found {
                    return Err(Error::from_str(404, "unauthorized object rufsGroup"));
                }
            } else {
                return Ok(());
            }
        } else {
            return Err(Error::from_str(404, "unauthorized object rufsGroupOwner"));
        }

        Err(Error::from_str(500, "unknow"))
    }

    async fn process_create(&mut self) -> tide::Response {
        if let Err(error) = self.check_object_access() {
            return tide::Response::builder(error.status()).body(error.to_string()).build();
        }

        let entity_manager = self.entity_manager.as_ref().unwrap();
        let openapi = &self.micro_service.micro_service_server.openapi;
        let new_obj = entity_manager.insert(openapi, &self.schema_name, &self.obj_in.clone()).await;

        match &new_obj {
            Ok(new_obj) => {
                self.notify(new_obj, false);
                tide::Response::builder(200).body(new_obj.clone()).build()
            },
            Err(error) => tide::Response::builder(500).body(error.to_string()).build(),
        }
    }

    async fn get_object(&self, use_document :bool) -> Result<Box<Value>, Error> {
        let key = self.parse_query_parameters(false)?;
        println!("[RequestFilter.get_object({})] : {}", self.schema_name, key);
        let entity_manager = self.entity_manager.as_ref().unwrap();
        let openapi = &self.micro_service.micro_service_server.openapi;
        let obj = entity_manager.find_one(openapi, &self.schema_name, &key).await.context(format!("Missing data in {} for key {}", self.schema_name, key))?;

        if use_document != true {
            return Ok(obj);
        }

        Err(Error::from_str(StatusCode::NotImplemented, "[ResquestFilter.GetObject] don't implemented com rf useDocument == true"))
    }

    async fn process_read(&self) -> tide::Response {
        println!("[RequestFilter.process_read({})]", self.schema_name);
        // TODO : check RequestBody schema
        match self.get_object(false).await {
            Ok(obj) => tide::Response::builder(200).body(obj.as_ref().clone()).build(),
            Err(error) => tide::Response::builder(error.status()).body(error.to_string()).build(),
        }
    }

    async fn process_update(&mut self) -> tide::Response {
        if let Err(error) = self.get_object(false).await {
            return tide::Response::builder(error.status()).body(error.to_string()).build();
        }

        if let Err(error) = self.check_object_access() {
            return tide::Response::builder(error.status()).body(error.to_string()).build();
        }

        let primary_key = &self.parse_query_parameters(false).unwrap();
        println!("[RequestFilter.process_update({})] : {}", self.schema_name, primary_key);
        let entity_manager = self.entity_manager.as_ref().unwrap();
        let new_obj = entity_manager.update(&self.micro_service.micro_service_server.openapi, &self.schema_name, primary_key, &self.obj_in).await;

        match new_obj {
            Ok(new_obj) => {
                self.notify(&new_obj, false);
                tide::Response::builder(200).body(new_obj.clone()).build()
            },
            Err(error) => tide::Response::builder(500).body(error.to_string()).build(),
        }
    }

    async fn process_delete(&mut self) -> tide::Response {
        let obj_deleted = match self.get_object(false).await {
            Ok(obj) => obj,
            Err(error) => return tide::Response::builder(error.status()).body(error.to_string()).build(),
        };

        let primary_key = &self.parse_query_parameters(false).unwrap();
        let entity_manager = self.entity_manager.as_ref().unwrap();
        let res = entity_manager.delete_one(&self.micro_service.micro_service_server.openapi, &self.schema_name, primary_key).await;

        if let Err(error) = res {
            return tide::Response::builder(500).body(error.to_string()).build();
        }

        self.notify(&obj_deleted, true);
        tide::Response::builder(200).body(obj_deleted.as_ref().clone()).build()
    }
/*
    func (rf *RequestFilter) processPatch() Response {
        return ResponseInternalServerError("TODO")
    }
*/
    fn parse_query_parameters(&self, ignore_null: bool) -> Result<Value, Error> {
        let obj = self.micro_service.micro_service_server.openapi.copy_fields(&self.path, &self.method, &SchemaPlace::Parameter, true, &self.parameters, ignore_null, false, false).unwrap();
        //println!("[openapi.parse_query_parameters({})] : {}", self.parameters, obj.to_string());
        Ok(obj)
    }

    async fn process_query(&self) -> tide::Response {
        fn get_order_by(properties: &IndexMap<String, ReferenceOr<Box<Schema>>>) -> Vec<String> {
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

        let schema = self.micro_service.micro_service_server.openapi.get_schema_from_parameters(&self.path, &self.method, true).unwrap();
        let fields = self.parse_query_parameters(true).unwrap();

        let order_by = match &schema.schema_kind {
            openapiv3::SchemaKind::Type(typ) => match typ {
                openapiv3::Type::Object(object_type) => get_order_by(&object_type.properties),
                _ => todo!(),
            },
            openapiv3::SchemaKind::Any(any) => get_order_by(&any.properties),
            _ => todo!(),
        };

        let list = self.entity_manager.as_ref().unwrap().find(&self.micro_service.micro_service_server.openapi, &self.schema_name, &fields, &order_by).await;
        println!("[RequestFilter.process_query] : returning {} registers.", list.len());
        tide::Response::builder(200).body(Value::Array(list)).build()
    }

    pub async fn check_authorization<State>(&mut self, req: &Request<State>) -> Result<bool, Error> {
        fn check_mask(mask: u64, method: &str) -> bool {
            let list = vec!["get", "post", "put", "patch", "delete", "query"];

            if let Some(idx) = list.iter().position(|&x| x == method) {
                (mask & (1 << idx)) != 0
            } else {
                false
            }
        }

        for security_item in self.micro_service.micro_service_server.openapi.security.as_ref().unwrap() {
            for (security_name, _) in security_item {
                let security_scheme = self.micro_service
                    .micro_service_server
                    .openapi
                    .components
                    .as_ref()
                    .unwrap()
                    .security_schemes
                    .get(security_name);

                if security_scheme.is_none()
                {
                    continue;
                }

                let security_scheme = security_scheme.unwrap().as_item().unwrap();

                match &security_scheme {
                    openapiv3::SecurityScheme::APIKey { location, name, description: _ } => match &location {
                        openapiv3::APIKeyLocation::Query => todo!(),
                        openapiv3::APIKeyLocation::Header => {
                            for header_name in req.header_names() {
                                if header_name.as_str().to_lowercase() == name.to_lowercase() {
                                    let header_array = req.header(header_name).unwrap();
                                    let token_raw = header_array.last().as_str();

                                    if let Some(_user) = self.micro_service.db_adapter_file.find_one(&self.micro_service.micro_service_server.openapi, "rufsUser", &json!({ "password": token_raw })).await.take() {
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
                    openapiv3::SecurityScheme::HTTP {
                        scheme,
                        bearer_format,
                        description: _,
                    } => {
                        if scheme == "bearer" && bearer_format.as_ref().unwrap() == "JWT" {
                            let authorization_header_prefix = "Bearer ";
                            let token_raw = req.header("Authorization").unwrap().last().as_str();

                            if token_raw.starts_with(authorization_header_prefix) {
                                let token_raw = &token_raw[authorization_header_prefix.len()..];
								let secret = std::env::var("RUFS_JWT_SECRET").unwrap_or("123456".to_string());
								let x = decode::<Claims>(&token_raw, &DecodingKey::from_secret(secret.as_ref()), &Validation::default()).unwrap();
								self.token_payload = Some(x.claims);
                            }
                        }
                    }
                    openapiv3::SecurityScheme::OAuth2 { flows: _, description: _ } => todo!(),
                    openapiv3::SecurityScheme::OpenIDConnect {
                        open_id_connect_url: _,
                        description: _,
                    } => todo!(),
                }
            }
        }

        if let Some(role) = self.token_payload.as_ref().unwrap().roles.as_ref().iter().find(|&x| x.path == self.path) {
            if check_mask(role.mask, &self.method) {
                Ok(true)
            } else {
                Ok(false)
            }
        } else {
            Err(Error::from_str(
                StatusCode::Unauthorized,
                format!("[RequestFilter.CheckAuthorization] missing service {}.{} in authorized roles", self.path, self.method),
            ))
        }
    }

    pub async fn process_request(&mut self) -> tide::Response {
        //let schema_response = self.micro_service.micro_service_server.openapi.get_schema(&self.path, &self.method, "responseObject").unwrap();
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
            return tide::Response::builder(tide::StatusCode::BadRequest).body(format!("[RequsetFilter.ProcessRequest] : unknow route for {}", self.path)).build();
        }
    }

    fn notify(&self, obj :&Value, is_remove :bool) {
        let micro_service = self.micro_service;
        let openapi = &micro_service.micro_service_server.openapi;
        let parameters = openapi.copy_fields(&self.path, &self.method, &SchemaPlace::Schemas, false, obj, false, false, true).unwrap();
        let mut msg = NotifyMessage{service: self.schema_name.to_string(), action: "notify".to_string(), primary_key: parameters};

        if is_remove {
            msg.action = "delete".to_string();
        }

        let msg = serde_json::to_string(&msg).unwrap();
        let obj_rufs_group_owner = openapi.get_primary_key_foreign(&self.schema_name, "rufsGroupOwner", obj).unwrap();
        let rufs_group = openapi.get_primary_key_foreign(&self.schema_name, "rufsGroup", obj).unwrap();
        println!("[RequestFilter.notify] broadcasting {:?} ...", msg);
        let map = micro_service.ws_server_connections.read().unwrap();

        for (token_string, ws_server_connection) in map.iter() {
            // enviar somente para os clients de "rufsGroupOwner"
            let key = &token_string.clone();
            let map = micro_service.ws_server_connections_tokens.read().unwrap();
            let token_data = map.get(key).unwrap();
            let mut check_rufs_group_owner = obj_rufs_group_owner.is_none();

            if check_rufs_group_owner == false {
                if let Some(id) = obj_rufs_group_owner.as_ref().unwrap().primary_key.get("id") {
                    if id.as_u64().unwrap() == token_data.rufs_group_owner {
                        check_rufs_group_owner = true;
                    }
                }
            }

            let mut check_rufs_group = rufs_group.is_none();

            if check_rufs_group == false {
                if let Some(id) = rufs_group.as_ref().unwrap().primary_key.get("id") {
                    if token_data.groups.contains(&id.as_u64().unwrap()) {
                        check_rufs_group = true;
                    }
                }
            }
            // restrição de rufsGroup
            if token_data.rufs_group_owner == 1 || (check_rufs_group_owner && check_rufs_group) {
                for role in token_data.roles.iter() {
                    if role.path == self.path {
                        if (role.mask & 0x01) != 0 {
                            println!("[RequestFilter.notify] send to client {}", token_data.name);
                            let rt = tokio::runtime::Runtime::new().unwrap();

                            if let Err(error) = rt.block_on(ws_server_connection.send_string(msg.to_string())) {
                                println!("[RequestFilter.notify] send to client : {}", error);
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
