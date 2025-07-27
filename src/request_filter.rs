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

#[cfg(not(target_arch = "wasm32"))]
#[cfg(feature = "http_server")]
pub async fn process_request<'b>(rms: &'b RufsMicroService<'b>, path: &'b str, query: Option<&'b str>, method: &'b str, headers_out: &HashMap<String, String>, mut obj_in: Value) -> Result<Value, Box<dyn std::error::Error>> {

    struct RequestFilter {
        path: String,
        query_params: Value,
        open_api_schema: String,
        db_schema: String
    }
    
    async fn check_authorization<'a, State>(rms: &'a RufsMicroService<'a>, headers: &'a HashMap<String, String>, path: &'a str, method: &'a str) -> Result<(bool, Claims, String), Box<dyn std::error::Error>> {
        fn check_mask(mask: u64, method: &str) -> bool {
            let list = vec!["get", "post", "put", "patch", "delete", "query"];

            if let Some(idx) = list.iter().position(|&x| x == method) {
                (mask & (1 << idx)) != 0
            } else {
                false
            }
        }

        fn get_token_payload(openapi: &openapiv3::OpenAPI, headers: &HashMap<String, String>) -> Result<Claims, Box<dyn std::error::Error>> {
            let mut token_payload = None;
    
            for security_item in openapi.security.as_ref().ok_or("Missing openapi.security")? {
                for (security_name, _) in security_item {
                    let Some(security_scheme) = openapi.components.as_ref().ok_or("Broken components")?.security_schemes.get(security_name) else {
                        continue;
                    };
    
                    let security_scheme = security_scheme.as_item().ok_or("Broken security_scheme.as_item()")?;
    
                    match &security_scheme {
                        openapiv3::SecurityScheme::APIKey { location, name: _, description: _ } => match &location {
                            openapiv3::APIKeyLocation::Query => todo!(),
                            openapiv3::APIKeyLocation::Header => todo!(),
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
                                    token_payload = Some(x.claims);
                                }
                            }
                        }
                        openapiv3::SecurityScheme::OAuth2 { flows: _, description: _ } => todo!(),
                        openapiv3::SecurityScheme::OpenIDConnect { open_id_connect_url: _, description: _ } => todo!(),
                    }
                }
            }
    
            let token_payload = token_payload.ok_or("Broken token_payload")?;
            Ok(token_payload)
        }
    
        let token_payload = get_token_payload(&rms.openapi, headers)?;

        if let Some(role) = token_payload.roles.iter().find(|&x| x.path == path) {
            if check_mask(role.mask, method) {
                let db_schema = if let Some(customer) = token_payload.extra.get("customer") {
                    "rufs_customer_".to_owned() + customer.as_str().ok_or("Broken customer_id data")?
                } else {
                    "public".to_string()
                };

                Ok((true, token_payload, db_schema))
            } else {
                Ok((false, token_payload, "".to_string()))
            }
        } else {
            Err(format!("404-[RequestFilter.CheckAuthorization] missing service {}.{} in authorized roles", path, method))?
        }
    }

    fn parse_query_parameters(rms: &RufsMicroService<'_>, rf: &RequestFilter, ignore_null: bool, method: &str) -> Result<Value, Box<dyn std::error::Error>> {
        let obj = rms.openapi.copy_fields(&rf.path, method, &SchemaPlace::Parameter, true, &rf.query_params, ignore_null, false, false).unwrap();
        //println!("[openapi.parse_query_parameters({})] : {}", self.parameters, obj.to_string());
        Ok(obj)
    }

    async fn get_object(rms: &RufsMicroService<'_>, rf: &RequestFilter, use_document :bool, method: &str) -> Result<Box<Value>, Box<dyn std::error::Error>> {
        let key = parse_query_parameters(rms, rf, false, method)?;
        let obj = rms.entity_manager.find_one(&rms.openapi, &rf.db_schema, &rf.open_api_schema, &key).await?.ok_or_else(|| format!("Missing data in {} for key {}", rf.open_api_schema, key))?;

        if use_document != true {
            return Ok(obj);
        }

        Err("[ResquestFilter.GetObject] don't implemented com rf useDocument == true")?
    }

    async fn process_query(rms: &RufsMicroService<'_>, rf: &RequestFilter, method: &str) -> Result<Value, Box<dyn std::error::Error>> {
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

        let schema = rms.openapi.get_schema_from_parameters(&rf.path, method, true).unwrap();
        let fields = parse_query_parameters(rms, rf, true, method).unwrap();

        let order_by = match &schema.schema_kind {
            openapiv3::SchemaKind::Type(typ) => match typ {
                openapiv3::Type::Object(object_type) => get_order_by(&object_type.properties),
                _ => todo!(),
            },
            openapiv3::SchemaKind::Any(any) => get_order_by(&any.properties),
            _ => todo!(),
        };

        let list = rms.entity_manager.find(&rms.openapi, &rf.db_schema, &rf.open_api_schema, &fields, &order_by).await?;
        println!("[RequestFilter.process_query] : returning {} registers.", list.len());
        Ok(Value::Array(list))
    }

    async fn process_read(rms: &RufsMicroService<'_>, rf: &RequestFilter, method: &str) -> Result<Value, Box<dyn std::error::Error>> {
        let obj = get_object(rms, rf, false, method).await?.as_ref().clone();
        Ok(obj)
    }

    fn notify(rms: &RufsMicroService<'_>, rf: &RequestFilter, obj :&Value, is_remove :bool, method: &str) {
        #[derive(Serialize, Deserialize, Debug)]
        #[serde(rename_all = "camelCase")]
        struct NotifyMessage {
            service    :String,
            action     :String,
            primary_key :Value
        }
        
        let parameters = rms.openapi.copy_fields(&rf.path, method, &SchemaPlace::Schemas, false, obj, false, false, true).unwrap();
        let mut msg = NotifyMessage{service: rf.open_api_schema.to_string(), action: "notify".to_string(), primary_key: parameters};

        if is_remove {
            msg.action = "delete".to_string();
        }

        let msg = serde_json::to_string(&msg).unwrap();
        let obj_rufs_group_owner = rms.openapi.get_primary_key_foreign(&rf.open_api_schema, "rufsGroupOwner", obj).unwrap();
        let rufs_group = rms.openapi.get_primary_key_foreign(&rf.open_api_schema, "rufsGroup", obj).unwrap();
        println!("[RequestFilter.notify] broadcasting {:?} ...", msg);
        #[cfg(feature = "tide")]
        let map = rms.ws_server_connections_tide.read().unwrap();
        #[cfg(feature = "warp")]
        let mut map = rms.ws_server_connections_warp.write().unwrap();

        for (token_string, ws_server_connection) in map.iter_mut() {
            // enviar somente para os clients de "rufsGroupOwner"
            let key = &token_string.clone();
            let map = rms.ws_server_connections_tokens.read().unwrap();
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
                    if role.path == rf.path {
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

        println!("[RequestFilter.notify] ...broadcasting");
    }

    fn check_object_access(rms: &RufsMicroService<'_>, rf: &mut RequestFilter, obj: &mut Value, token_payload: &Claims) -> Result<(), Box<dyn std::error::Error>> {
        let user_rufs_group_owner = &token_payload.rufs_group_owner;

        if user_rufs_group_owner == "admin" {
            return Ok(());
        }

        let mut obj_rufs_group_owner = if let Some(obj_rufs_group_owner) = rms.openapi.get_primary_key_foreign(&rf.open_api_schema, "rufsGroupOwner", obj)? {
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
            if let Some(rufs_group) = rms.openapi.get_primary_key_foreign(&rf.open_api_schema, "rufsGroup", obj)? {
                let rufs_group_id = rufs_group.primary_key.get("name").unwrap().as_str().unwrap().to_string();
                let mut found = false;

                for group in token_payload.groups.as_ref().iter().as_ref() {
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

    async fn process_create(rms: &RufsMicroService<'_>, rf: &mut RequestFilter, obj_in: &mut Value, token_payload: &Claims) -> Result<Value, Box<dyn std::error::Error>> {
        check_object_access(rms, rf, obj_in, token_payload)?;
        let new_obj = rms.entity_manager.insert(&rms.openapi, &rf.db_schema, &rf.open_api_schema, obj_in).await?;
        Ok(new_obj)
    }

    async fn process_update(rms: &RufsMicroService<'_>, rf: &mut RequestFilter, obj_in: &mut Value, token_payload: &Claims, method: &str) -> Result<Value, Box<dyn std::error::Error>> {
        check_object_access(rms, rf, obj_in, token_payload)?;
        let primary_key = parse_query_parameters(rms, rf, false, method).unwrap();
        let new_obj = rms.entity_manager.update(&rms.openapi, &rf.db_schema, &rf.open_api_schema, &primary_key, obj_in).await?;
        notify(rms, rf, &new_obj, false, method);
        Ok(new_obj)
    }

    async fn process_delete(rms: &RufsMicroService<'_>, rf: &mut RequestFilter, method: &str) -> Result<Value, Box<dyn std::error::Error>> {
        let obj_deleted = get_object(rms, rf, false, method).await?;
        let primary_key = parse_query_parameters(rms, rf, false, method).unwrap();
        rms.entity_manager.delete_one(&rms.openapi, &rf.db_schema, &rf.open_api_schema, &primary_key).await?;
        notify(rms, rf, &obj_deleted, true, method);
        Ok(obj_deleted.as_ref().clone())
    }

    let query_params = if let Some(query) = query {
        queryst::parse(query).unwrap()
    } else {
        Value::default()
    };

    let path = if let Some(pos) = path.find(&format!("/{}/", rms.params.api_path)) {
        &path[pos + 1 + rms.params.api_path.len()..]
    } else {
        path
    };

    let path = rms.openapi.get_path_params(path, &query_params).unwrap();
    let (authorized, token_payload, db_schema) = check_authorization::<RufsMicroService>(rms, &headers_out, &path, method).await?;

    if authorized == false {
        return Err("401-Unauthorized.")?
    }

    let open_api_schema = rms.openapi.get_schema_name(&path, method, false).unwrap();
    let mut rf = RequestFilter {path, open_api_schema, db_schema, query_params};

    if method == "get" {
        let may_be_array = match &rf.query_params {
            Value::Object(obj) => !(obj.contains_key("id") || obj.contains_key("primaryKey")),
            _ => true,
        };

        if may_be_array {
            return process_query(rms, &rf, method).await
        } else {
            return process_read(rms, &rf, method).await
        }
    } else if method == "post" {
        return process_create(rms, &mut rf, &mut obj_in, &token_payload).await;
    } else if method == "put" {
        return process_update(rms, &mut rf, &mut obj_in, &token_payload, method).await;
    } else if method == "delete" {
        return process_delete(rms, &mut rf, method).await;
    } else {
        return Err(format!("400-[RequsetFilter.ProcessRequest] : unknow route for {}", rf.path))?;
    }
}
