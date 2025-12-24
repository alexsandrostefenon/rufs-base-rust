use std::{collections::HashMap, fs, path::Path, sync::Arc};
use serde::{Deserialize, Serialize};
use serde_json::{Value,json};
use openapiv3::{OpenAPI, SecurityRequirement};
use jsonwebtoken::{encode, EncodingKey, Header};
use async_std::path::PathBuf;
use async_trait::async_trait;
use tokio::sync::{Mutex, RwLock};

use crate::{db_adapter_postgres::DbAdapterSql,entity_manager::EntityManager,openapi::{FillOpenAPIOptions, RufsOpenAPI, Role}};

#[derive(Deserialize, Serialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct Route {
    path: String,
    controller: String,
    #[serde(default)]
    template_url: String,
}

#[derive(Deserialize, Serialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct MenuItem {
    group: String,
    label: String,
    path: String,
}

#[derive(Deserialize, Serialize, Default)]
#[serde(default)]
#[serde(rename_all = "camelCase")]
pub struct RufsUser {
    pub name: String,
    pub rufs_group_owner: String,
    pub groups: Box<[String]>,
    pub roles: Vec<Role>,
    pub routes: Box<[Route]>,
    pub menu: Box<[MenuItem]>,
    pub path: String,
    pub full_name: String,
    pub password: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LoginResponse<'a> {
    pub jwt_header: String,
    pub openapi: &'a OpenAPI,
    pub name: String,
    pub rufs_group_owner: String,
    pub groups: Box<[String]>,
    pub roles: Vec<Role>,
    pub ip: String,
    pub path: String,
    pub title: String,
    routes: Box<[Route]>,
    menu: Box<[MenuItem]>,
    extra: Value
}

#[derive(Debug, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct Claims {
    sub: String,
    exp: usize,
    pub name: String,
    pub rufs_group_owner: String,
    pub groups: Box<[String]>,
    pub roles: Vec<Role>,
    ip: String,
    pub extra: Value
}

#[derive(serde::Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct LoginRequest {
    pub user: String,
    pub password: String,
}

#[async_trait]
pub trait Authenticator {
    async fn authenticate_user(&self, rufs: &RufsMicroService, user_name: &str, user_password: &str) -> Result<(RufsUser, Value, Value), Box<dyn std::error::Error>>;
}

#[derive(Clone)]
pub struct RufsParams {
    pub app_name: String,
    pub port: u16,
    pub api_path: String,
    pub request_body_content_type: String,
    pub openapi_file_name : String
}

impl Default for RufsParams {
    fn default() -> Self {
        Self {
            port: 8080,
            api_path: "rest".to_string(),
            app_name: "base".to_string(),
            request_body_content_type: "application/json".to_string(),
            openapi_file_name: "".to_string()
        }
    }
}

#[derive(Clone)]
pub struct RufsMicroService<'a> {
    pub params: RufsParams,
    pub openapi: OpenAPI,
    pub watcher: &'static Box<dyn DataViewWatch>,
    pub entity_manager: DbAdapterSql<'a>,
    pub web_socket_server_connections_tokens : Arc<RwLock<HashMap<String, Claims>>>,
    #[cfg(feature = "tide")]
    pub ws_server_connections_tide : Arc<RwLock<HashMap<String, tide_websockets::WebSocketConnection>>>,
    #[cfg(feature = "warp")]
    pub web_socket_server_connections_warp : Arc<RwLock<HashMap<String, futures_util::stream::SplitSink<warp::ws::WebSocket, warp::ws::Message>>>>,
}

impl RufsMicroService<'_> {
    pub fn build_db_uri(host: Option<&str>, port: Option<&str>, user: Option<&str>, password: Option<&str>, database: Option<&str>, schema: Option<&str>) -> String {
        fn get_value(key: &str, value: Option<&str>, default: &str) -> String {
            match std::env::var(key) {
                Ok(value) => value,
                Err(_) => match value {
                    Some(value) => value.to_string(),
                    None => default.to_string(),
                }
            }
        }

        let host = get_value("PGHOST", host, "localhost");
        let port = get_value("PGPORT", port, "5432");
        let user = get_value("PGUSER", user, "development");
        let password = get_value("PGPASSWORD", password, "123456");

        let database = if let Some(database) = database {
            database.to_string()
        } else {
            get_value("PGDATABASE", database, "rufs_base")
        };

        let options = if let Some(schema) = schema {
            "?options=-c%20search_path=".to_owned() + schema
        } else {
            String::new()
        };

        format!("postgres://{user}:{password}@{host}:{port}/{database}{options}")
    }

    fn load_open_api(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        if self.params.openapi_file_name.is_empty() {
            self.params.openapi_file_name = format!("openapi-{}.json", self.params.app_name);
        }

        println!("[MicroServiceServer.load_open_api({}/{})]", std::env::current_dir().unwrap().to_string_lossy(), self.params.openapi_file_name);

        match fs::File::open(&self.params.openapi_file_name) {
            Ok(file) => self.openapi = serde_json::from_reader(file)?,
            Err(error) => match error.kind() {
                std::io::ErrorKind::NotFound => self.openapi = OpenAPI::default(),
                _ => todo!(),
            }
        }

        self.openapi.create("jwt");
        Ok(())
    }

    pub fn store_open_api(&self) -> Result<(), Box<dyn std::error::Error>> {
        let contents = serde_json::to_string_pretty(&self.openapi)?;
        std::fs::write(&self.params.openapi_file_name, contents)?;
        Ok(())
    }

    pub async fn connect<'a>(db_uri: &str, migration_path: &str, params: RufsParams, watcher: &'static Box<dyn DataViewWatch>) -> Result<RufsMicroService<'a>, Box<dyn std::error::Error>> {
        async fn create_rufs_tables(rms: &RufsMicroService<'_>, openapi_rufs: &OpenAPI) -> Result<(), Box<dyn std::error::Error>> {
            let db_schema = "rufs_customer_template";
            rms.entity_manager.exec("CREATE SCHEMA IF NOT EXISTS rufs_customer_template;").await?;

            for name in ["rufsGroupOwner", "rufsUser", "rufsGroup"] { // , "rufsGroupUser"
                println!("[connect.create_rufs_tables] check table {name}...");

                if rms.openapi.components.as_ref().unwrap().schemas.get(name).is_none() {
                    println!("don't matched schema {}, existents :\n{:?}", name, rms.openapi.components.as_ref().unwrap().schemas.keys());
                    let schema = openapi_rufs.components.as_ref().unwrap().schemas.get(name).unwrap().as_item().unwrap();
                    rms.entity_manager.create_table(db_schema, &name, schema).await?;
                    println!("[connect.create_rufs_tables] ... table {name} created!");
                } else {
                    println!("[connect.create_rufs_tables] ... table {name} already exists.");
                }
            }

            let default_group_owner_admin: serde_json::Value = serde_json::from_str(DEFAULT_GROUP_OWNER_ADMIN_STR).unwrap();
            let default_user_admin: serde_json::Value = serde_json::from_str(DEFAULT_USER_ADMIN_STR).unwrap();

            if rms.entity_manager.find_one(openapi_rufs, db_schema, "rufsGroupOwner", &json!({"name": "admin"})).await?.is_none() {
                rms.entity_manager.insert(openapi_rufs, db_schema, "rufsGroupOwner", &default_group_owner_admin).await?;
            }

            if rms.entity_manager.find_one(openapi_rufs, db_schema, "rufsUser", &json!({"name": "admin"})).await?.is_none() {
                rms.entity_manager.insert(openapi_rufs, db_schema, "rufsUser", &default_user_admin).await?;
            }

            Ok(())
        }

        async fn exec_migrations(rms: &mut RufsMicroService<'_>, migration_path: &str) -> Result<bool, Box<dyn std::error::Error>> {
            async fn migrate(rms: &mut RufsMicroService<'_>, migration_path: &str, file_name: &str) -> Result<(), Box<dyn std::error::Error>> {
                println!("Migrating to version {}...", file_name);
                let text = fs::read_to_string(PathBuf::from(migration_path).join(file_name))?;

                for sql in text.split("--split") {
                    rms.entity_manager.exec(sql).await?;
                }

                let new_version = crate::openapi::parse_version_number(file_name)?;
                rms.openapi.info.version = format!("{}.{}.{}", ((new_version / 1000) / 1000) % 1000, (new_version / 1000) % 1000, new_version % 1000);
                println!("... Migrated version {}", file_name);
                Ok(())
            }

            if Path::new(migration_path).exists() == false {
                return Ok(false);
            }

            let old_version = crate::openapi::parse_version_number(&rms.openapi.info.version)?;
            let files = fs::read_dir(migration_path)?;
            let mut list: Vec<String> = vec![];

            for file_info in files {
                let path = file_info.unwrap().file_name().into_string().unwrap();
                let version = crate::openapi::parse_version_number(&path)?;

                if version > old_version {
                    list.push(path);
                }
            }

            list.sort_by(|a, b| {
                let version_i = crate::openapi::parse_version_number(a).unwrap();
                let version_j = crate::openapi::parse_version_number(b).unwrap();
                return version_i.cmp(&version_j);
            });

            for file_name in &list {
                migrate(rms, migration_path, file_name).await?;
            }

            Ok(list.len() > 0)
        }

        let mut rufs = RufsMicroService {
            params,
            watcher,
            openapi: Default::default(),
            entity_manager: DbAdapterSql::default(),
            web_socket_server_connections_tokens: Arc::default(),
            #[cfg(feature = "tide")]
            ws_server_connections_tide: Arc::default(),
            #[cfg(feature = "warp")]
            web_socket_server_connections_warp: Arc::default(),
        };

        println!("[connect] : load_open_api...");
        rufs.load_open_api()?;
        println!("[connect] : entity_manager.connect...");
        rufs.entity_manager.connect(db_uri).await?;
        println!("[connect] : parsing static openapi_rufs...");
        let openapi_rufs = serde_json::from_str::<OpenAPI>(RUFS_MICRO_SERVICE_OPENAPI_STR)?;
        println!("[connect] : create_rufs_tables...");
        create_rufs_tables(&rufs, &openapi_rufs).await?;
        println!("[connect] : exec_migrations...");

        if exec_migrations(&mut rufs, migration_path).await? {
            println!("[connect] : pg_dump --inserts -n rufs_customer_template -f data/rufs_customer_template.sql...");
            #[cfg(debug_assertions)]
            let status = std::process::Command::new("/usr/bin/podman").arg("exec").arg("postgres").arg("pg_dump").arg(db_uri).arg("--inserts").arg("-n").arg("rufs_customer_template").arg("-f").arg("/app/data/rufs_customer_template.sql").status().expect("Failed to run pg_dump");
            #[cfg(not(debug_assertions))]
            let status = std::process::Command::new("pg_dump").arg(db_uri).arg("--inserts").arg("-n").arg("rufs_customer_template").arg("-f").arg("data/rufs_customer_template.sql").status().expect("Failed to run pg_dump");

            if status.success() == false {
                return Err("Broken pg_dump")?;
            }
        }

        let mut options = FillOpenAPIOptions::default();
        options.request_body_content_type = rufs.params.request_body_content_type.clone();
        println!("[connect] : update_open_api...");
        rufs.entity_manager.update_open_api(&mut rufs.openapi, &mut options).await?;
        let mut options = FillOpenAPIOptions::default();
        options.security = SecurityRequirement::from([("jwt".to_string(), vec![])]);
        options.schemas = openapi_rufs.components.ok_or("missing section components")?.schemas.clone();
        options.request_body_content_type = rufs.params.request_body_content_type.clone();
        println!("[connect] : openapi.fill...");
        rufs.openapi.fill(&mut options)?;
        println!("[connect] : store_open_api...");
        rufs.store_open_api()?;
        Ok(rufs)
    }

    pub fn build_login_response(&self, user: RufsUser, remote_addr: &str, extra_claims: Value, extra: Value) -> Result<LoginResponse<'_>, Box<dyn std::error::Error>> {
        let claims = Claims {
            sub: "".to_string(),
            exp: 10000000000,
            name: user.name,
            rufs_group_owner: user.rufs_group_owner.clone(),
            groups: Box::new([]),
            roles: user.roles,
            ip: remote_addr.to_string(),
            extra: extra_claims
        };

        let secret = std::env::var("RUFS_JWT_SECRET").unwrap_or("123456".to_string());
        let jwt_header = encode(&Header::default(), &claims, &EncodingKey::from_secret(secret.as_ref()))?;

        let login_response = LoginResponse {
            jwt_header,
            openapi: &self.openapi,
            name: claims.name.clone(),
            rufs_group_owner: claims.rufs_group_owner,
            groups: claims.groups,
            roles: claims.roles,
            ip: claims.ip.clone(),
            title: claims.name,
            routes: user.routes,
            menu: user.menu,
            path: user.path.clone(),
            extra
        };

        Ok(login_response)
    }

}

#[derive(Clone)]
pub struct RufsMicroServiceAuthenticator();

#[async_trait]
impl Authenticator for RufsMicroServiceAuthenticator {

    async fn authenticate_user(&self, rufs: &RufsMicroService, customer_user: &str, user_password: &str) -> Result<(RufsUser, Value, Value), Box<dyn std::error::Error>> {
        let re = regex::Regex::new(r"^((?P<customer_id>\d{11,14}|\d{3}\.\d{3}\.\d{3}\-\d{2}|\d{2}\.\d{3}\.\d{3}/\d{4}\-\d{2})\.)?(?P<user_id>.*)")?;

        let Some(cap) = re.captures(customer_user) else {
            return Err("Broken customer_user.")?
        };

        let Some(user_id) = cap.name("user_id") else {
            return Err("Broken customer_user, missing user_name.")?
        };

        let (db_schema, customer_id) = match cap.name("customer_id") {
            Some(customer_id) => {
                let re = regex::Regex::new(r"[^\d]")?;
                let customer_id = re.replace_all(customer_id.as_str(), "").to_string();
                ("rufs_customer_".to_owned() + &customer_id, customer_id)
            },
            _ => {
                ("public".to_string(), "".to_string())
            },
        };

        let openapi_schema = "rufsUser";
        rufs.entity_manager.check_schema(&db_schema, user_id.as_str(), user_password).await?;
        let user = rufs.entity_manager.find_one(&rufs.openapi, &db_schema, &openapi_schema, &json!({ "name": user_id.as_str() })).await?.ok_or("Fail to find user.")?;
        let user = RufsUser::deserialize(user)?;

        if user.password.len() > 0 && user.password != user_password {
            return Err("Don't match user and password.")?;
        }
        // user, extra_claims, extra
        let extra_claims = json!({"customer": customer_id});
        let extra = json!({});
        Ok((user, extra_claims, extra))
    }

}

use crate::client::DataViewWatch;

lazy_static::lazy_static! {
    static ref DATA_VIEW_MANAGER_MAP: tokio::sync::Mutex<std::collections::HashMap<String, crate::client::DataViewManager<'static>>>  = {
        let data_view_manager_map = std::collections::HashMap::new();
        tokio::sync::Mutex::new(data_view_manager_map)
    };
}

async fn wasm_ws_login(rms: &RufsMicroService<'_>, server_url: &str, path: &str, data_in: Value) -> Result<Value, Box<dyn std::error::Error>> {
    let mut data_view_manager_map = DATA_VIEW_MANAGER_MAP.lock().await;
    let mut data_view_manager = crate::client::DataViewManager::new(server_url, rms.watcher);
    let data_out = data_view_manager.login(path, data_in).await?;
    data_view_manager_map.insert(data_view_manager.server_connection.login_response.jwt_header.clone(), data_view_manager);
    Ok(data_out.into())
}

async fn wasm_ws_process(token_raw: &str, data_in: Value) -> Result<Value, Box<dyn std::error::Error>> {
    let authorization_header_prefix = "Bearer ";

    let jwt = if token_raw.starts_with(authorization_header_prefix) {
        &token_raw[authorization_header_prefix.len()..]
    } else {
        return Err("broken token")?;
    };

    let mut data_view_manager_map = DATA_VIEW_MANAGER_MAP.lock().await;
    let data_view_manager = data_view_manager_map.get_mut(jwt).ok_or("Missing session")?;
    data_view_manager.process(data_in).await
}

#[cfg(feature = "tide")]
pub async fn rufs_tide(app: &mut Box<tide::Server<RufsMicroService<'static>>>) -> Result<(), Box<dyn std::error::Error>> {
    use jsonwebtoken::{decode, DecodingKey, Validation};
    use std::{future::Future, pin::Pin};
    use tide::{Response, Next, Body};

    use crate::request_filter::RequestFilter;

    async fn handle_login(mut request: tide::Request<RufsMicroService<'_>>) -> tide::Result {
        //println!("[handle_login] : {:?}", request);
        let obj_in = request.body_json::<Value>().await?;
        println!("\n\ncurl -X '{}' {} -d '{}'", request.method(), request.url(), obj_in);
        let login_request = serde_json::from_value::<LoginRequest>(obj_in).unwrap();//request.body_json::<LoginRequest>().await?;
        let rufs = request.state();

        if login_request.user.is_empty() || login_request.password.is_empty() {
            println!("Login request is empty");
        }

        let login_response = match rufs.authenticate_user(&login_request.user, &login_request.password, request.remote().unwrap()).await {
            Ok(login_response) => login_response,
            Err(error) => {
                let msg = error.to_string();
                let response = Response::builder(tide::StatusCode::Unauthorized).body(msg).build();
                return Ok(response);
            }
        };

        Ok(Response::builder(tide::StatusCode::Ok).body(Body::from_json(&login_response)?).build())
    }

    async fn handle_api(mut request: tide::Request<RufsMicroService<'_>>) -> tide::Result {
        fn build_response(data :Result<Value, Box<dyn std::error::Error>>) -> tide::Result {
            let response = match data {
                Ok(value) => tide::Response::builder(tide::StatusCode::Ok).body(value).build(),
                Err(err) => {
                    let err = err.to_string();
                    let str_status = &err[0..4];

                    let status = match str_status {
                        "401" => tide::StatusCode::Unauthorized,
                        _ => tide::StatusCode::BadRequest
                    };

                    tide::Response::builder(status)
                    .body(format!("[RufsMicroService.OnRequest.CheckAuthorization] : {}", err))
                    .build()
                },
            };

            Ok(response)
        }

        let method = request.method().to_string().to_lowercase();
        let auth = request.header("Authorization").unwrap().as_str();
        println!("\n\ncurl -X '{}' {} -H 'Authorization: {}'", method, request.url(), auth);

        let obj_in = if ["post", "put", "patch"].contains(&method.as_str()) {
            let obj_in = request.body_json::<Value>().await?;
            println!(" -d '{}'", obj_in);
            obj_in
        } else {
            println!();
            Value::Null
        };

        let rufs = request.state();
        let path = request.url().path();
        let query = request.url().query();
        let mut rf = RequestFilter::new(rufs, path, query, &method, obj_in).unwrap();
        let mut headers: HashMap<String, String> = HashMap::new();

        for header_name in request.header_names() {
            if let Some(text) = request.header(header_name) {
                let name = header_name.as_str().to_lowercase();
                let text = text.as_str().to_string();
                headers.insert(name, text);
            }
        }

        let response = match rf.check_authorization::<RufsMicroService>(&headers).await {
            Ok(true) => build_response(rf.process_request().await),
            Ok(false) => Ok(Response::builder(tide::StatusCode::Unauthorized).build()),
            Err(err) => build_response(Err(err)),
        };

        response
    }

    fn static_paths_tide<'a>(request: tide::Request<RufsMicroService<'static>>, next: Next<'a, RufsMicroService<'static>>) -> Pin<Box<dyn Future<Output = tide::Result> + Send + 'a>> {
        Box::pin(async {
            if request.method() == tide::http::Method::Options {
                let acess_control_request_headers = match request.header("Access-Control-Request-Headers") {
                    Some(value) => value.to_string(),
                    None => "".to_string(),
                };

                let mut response = next.run(request).await;
                response.insert_header("Access-Control-Allow-Origin", "*");
                response.insert_header("Access-Control-Allow-Methods", "GET, PUT, OPTIONS, POST, DELETE");
                response.insert_header("Access-Control-Allow-Headers", acess_control_request_headers);
                return Ok(response);
            }

            if request.method() != tide::http::Method::Get {
                return Ok(next.run(request).await);
            }

            let rufs = request.state();

            match static_paths(rufs, request.url().path()).await {
                Ok(res) => match res {
                    Some(file) => match tide::Body::from_file(&file).await {
                        Ok(body) => return Ok(Response::builder(tide::StatusCode::Ok).body(body).build()),
                        Err(e) => return Err(e.into()),
                    },
                    None => return Ok(next.run(request).await),
                },
                Err(err) => return Ok(Response::builder(tide::StatusCode::BadRequest).body(err.to_string()).build()),
            }
        })
    }

    let rufs = app.state();
    let api_path = rufs.params.api_path.clone();

    app.at("/websocket").get(tide_websockets::WebSocket::new(|request, mut stream| async move {
        while let Some(Ok(tide_websockets::Message::Text(token))) = async_std::stream::StreamExt::next(&mut stream).await {
            let wsc = stream.clone();
            let rufs :&RufsMicroService= request.state();
            rufs.ws_server_connections_tide.write().unwrap().insert(token.clone(), wsc);
            let secret = std::env::var("RUFS_JWT_SECRET").unwrap_or("123456".to_string());
            let token_data = decode::<Claims>(&token, &DecodingKey::from_secret(secret.as_ref()), &Validation::default())?;
            rufs.ws_server_connections_tokens.write().unwrap().insert(token, token_data.claims);
        }

        Ok(())
    }));

    let path_login = format!("/{}/login", &api_path);
    app.at(&path_login).post(handle_login);
    let path_api = format!("/{}/*", &api_path);
    println!("[rufs_tide_new] listening api at {}...", path_api);
    app.at(&path_api).all(handle_api);
    app.with(static_paths_tide);

    async fn wasm_login_tide(mut req: tide::Request<RufsMicroService<'_>>) -> tide::Result {
        let data_in = req.body_json::<Value>().await?;
        let rms = req.state();

        let data_out = match wasm_ws_login(rms, data_in).await {
            Ok(data_out) => data_out,
            Err(err) => {
                let mut response = tide::Response::from(err.to_string());
                response.set_status(401);
                return Ok(response);
            }
        };

        Ok(data_out.into())
    }

    app.at("/wasm_ws/login").post(wasm_login_tide);

    async fn wasm_process_tide(mut req: tide::Request<RufsMicroService<'_>>) -> tide::Result {
        let token_raw = &req.header("Authorization").context("Missing header Authorization")?.last().as_str().to_string();
        let data_in = req.body_json::<Value>().await?;

        let data_out = match wasm_ws_process(token_raw, data_in).await {
            Ok(data_out) => data_out,
            Err(err) => {
                let mut response = tide::Response::from(err.to_string());
                response.set_status(500);
                return Ok(response);
            }
        };

        Ok(data_out.into())
    }

    app.at("/wasm_ws/process").post(wasm_process_tide);
    Ok(())
}

#[cfg(feature = "warp")]
pub fn rufs_warp_with_rufs(rufs: Arc<Mutex<RufsMicroService<'static>>>) -> impl warp::Filter<Extract = (Arc<Mutex<RufsMicroService<'static>>>,), Error = std::convert::Infallible> + Clone {
    use warp::Filter;
    warp::any().map(move || {
        rufs.clone()
    })
}

#[cfg(feature = "warp")]
pub async fn rufs_warp<'a, T>(rufs: &Arc<Mutex<RufsMicroService<'static>>>, authenticator: &'a T) -> impl warp::Filter<Extract = (impl warp::Reply + 'a,), Error = warp::Rejection> + Clone + 'a where T : Authenticator + std::marker::Send + Sync {
    use std::{convert::Infallible};
    use jsonwebtoken::{decode, DecodingKey, Validation};
    use futures_util::StreamExt;
    use warp::Reply;
    use warp::http::{Method, HeaderMap, StatusCode};
    use warp::path::FullPath;
    use warp::Filter;
    use warp::ws::WebSocket;

    macro_rules! warp_try {
        ($expr:expr) => {
            match $expr {
                Ok(val) => val,
                Err(err) => {
                    let err_str = err.to_string();
                    let str_status = &err_str[0..5];

                    let mut message = if (err_str.len() >= 5) {
                        &err_str[5..]
                    } else {
                        &err_str
                    };

                    let status = match str_status {
                        "401" => StatusCode::UNAUTHORIZED,
                        _ => {
                            message = &err_str;
                            StatusCode::BAD_REQUEST
                        }
                    };

                    let response = Box::new(warp::reply::with_status(message.to_string(), status)) as Box<dyn Reply>;
                    return Ok(response);
                }
            }
        };
    }

    let api_path = {
        rufs.lock().await.params.api_path.clone()
    };

    async fn handle_api(rufs: Arc<Mutex<RufsMicroService<'static>>>, method: Method, path: &str, headers: HeaderMap, query: String, obj_in: Value) -> Result<impl Reply + use<>, Infallible> {
        let method = method.to_string().to_lowercase();

        let query = if !query.is_empty() {
            Some(query.as_str())
        } else {
            None
        };

        let mut headers_out: HashMap<String, String> = HashMap::new();

        for (name, value) in &headers {
            let key = name.to_string().to_lowercase();
            let value = warp_try!(value.to_str());
            headers_out.insert(key, value.to_string());
        }

        #[cfg(debug_assertions)]
        {
            let header = warp_try!(headers.get("Authorization").ok_or("400-Missing Authorization header."));
            let auth = warp_try!(header.to_str());
            println!("\n\ncurl -X '{method}' {path}?{:?} -H 'Authorization: {auth}'", query);
        }

        let rufs = &rufs.lock().await.to_owned();
        let ret = warp_try!(crate::request_filter::process_request(rufs, path, query, &method, &headers_out, obj_in).await);
        let ret = warp::reply::json(&ret);
        #[cfg(debug_assertions)]
        println!("[handle_api()] : ...exiting");
        Ok(Box::new(ret))
    }

    async fn handle_api_put(rufs: Arc<Mutex<RufsMicroService<'static>>>, method: Method, path: FullPath, headers: HeaderMap, query: String, obj_in: Value) -> Result<impl Reply, Infallible> {
        handle_api(rufs, method, path.as_str(), headers, query, obj_in).await
    }

    let route_api_put = warp::path(api_path.clone()).
        and(rufs_warp_with_rufs(rufs.clone())).and(warp::method()).and(warp::path::full()).and(warp::header::headers_cloned()).
        and(warp::query::raw()).and(warp::body::json()).and_then(handle_api_put);

    async fn handle_api_post(rufs: Arc<Mutex<RufsMicroService<'static>>>, method: Method, path: FullPath, headers: HeaderMap, obj_in: Value) -> Result<impl Reply, Infallible> {
        handle_api(rufs.clone(), method, path.as_str(), headers, String::new(), obj_in).await
    }

    let route_api_post = warp::path(api_path.clone()).
        and(rufs_warp_with_rufs(rufs.clone())).and(warp::method()).and(warp::path::full()).and(warp::header::headers_cloned()).and(warp::body::json()).
        and_then(handle_api_post);

    async fn handle_api_get_delete(rufs: Arc<Mutex<RufsMicroService<'static>>>, method: Method, path: FullPath, headers: HeaderMap, query: String) -> Result<impl Reply, Infallible> {
        handle_api(rufs.clone(), method, path.as_str(), headers, query, json!({})).await
    }

    let route_api_get_delete = warp::path(api_path.clone()).
        and(rufs_warp_with_rufs(rufs.clone())).and(warp::method()).and(warp::path::full()).and(warp::header::headers_cloned()).and(warp::query::raw()).
        and_then(handle_api_get_delete);

    async fn handle_api_list_all(rufs: Arc<Mutex<RufsMicroService<'static>>>, method: Method, path: FullPath, headers: HeaderMap) -> Result<impl Reply, Infallible> {
        handle_api(rufs.clone(), method, path.as_str(), headers, String::new(), json!({})).await
    }

    let route_api_list_all = warp::path(api_path.clone()).
        and(rufs_warp_with_rufs(rufs.clone())).and(warp::method()).and(warp::path::full()).and(warp::header::headers_cloned()).
        and_then(handle_api_list_all);

    async fn handle_web_socket(rufs: Arc<Mutex<RufsMicroService<'static>>>, ws: warp::ws::Ws) -> Result<impl Reply, Infallible> {
        async fn user_connected(ws: WebSocket, rufs: Arc<Mutex<RufsMicroService<'static>>>) {
            let (user_ws_tx, mut user_ws_rx) = ws.split();

            if let Some(Ok(msg)) = user_ws_rx.next().await {
                if let Ok(token) = msg.to_str() {
                    let rufs = rufs.lock().await.to_owned();
                    let secret = std::env::var("RUFS_JWT_SECRET").unwrap_or("123456".to_string());

                    if let Ok(token_data) = decode::<Claims>(&token, &DecodingKey::from_secret(secret.as_ref()), &Validation::default()) {
                        rufs.web_socket_server_connections_warp.write().await.insert(token.to_string(), user_ws_tx);
                        rufs.web_socket_server_connections_tokens.write().await.insert(token.to_string(), token_data.claims);
                    }
                }
            }
        }

        let res = ws.on_upgrade(move |socket| user_connected(socket, rufs));
        Ok(res)
    }

    let route_websocket = warp::path("websocket").and(rufs_warp_with_rufs(rufs.clone())).and(warp::ws()).and_then(handle_web_socket);

    async fn wasm_ws_login_warp(rufs: Arc<Mutex<RufsMicroService<'static>>>, full_path: FullPath, data_in: Value, _remote: Option<std::net::SocketAddr>) -> Result<impl Reply, Infallible> {
        let rufs = &rufs.lock().await.to_owned();
        let full_path_str = full_path.as_str();

        let path = if let Some(pos) = full_path_str.find("/wasm_ws/") {
            &full_path_str[0..pos]
        } else {
            &full_path_str
        };

        let server_url = format!("http://localhost:{}{}", rufs.params.port, path);
        let ret = warp_try!(wasm_ws_login(rufs, &server_url, "/login", data_in).await);
        Ok(Box::new(warp::reply::json(&ret)))
    }

    let route_wasm_login = warp::path("wasm_ws").and(warp::path("login")).and(rufs_warp_with_rufs(rufs.clone())).and(warp::path::full()).and(warp::body::json()).and(warp::addr::remote()).and_then(wasm_ws_login_warp);

    async fn handle_login<T>(rufs: Arc<Mutex<RufsMicroService<'static>>>, login_request: LoginRequest, remote: Option<std::net::SocketAddr>, authenticator: &T) -> Result<impl Reply, Infallible> where T : Authenticator + std::marker::Send + Sync {
        let rufs = &rufs.lock().await.to_owned();
        let (user, extra_claims, extra) = warp_try!(authenticator.authenticate_user(rufs, &login_request.user, &login_request.password).await);
        let remote = warp_try!(remote.ok_or("400-Missing remote address."));
        let login_response = warp_try!(rufs.build_login_response(user, &remote.to_string(), extra_claims, extra));
        Ok(Box::new(warp::reply::json(&login_response)))
    }
/*
    async fn handle_options(h: HeaderMap) -> Result<impl Reply, Infallible> {
        let res = warp::reply();
        Ok(Box::new(res))
    }

    let cors = warp::cors().allow_any_origin().allow_methods(vec!["GET", "PUT", "OPTIONS", "POST", "DELETE"]).allow_headers(vec!["access-control-allow-origin","content-type"]);
    let route_options = warp::options().and(warp::header::headers_cloned()).and_then(handle_options).with(cors);
*/
    let route_login = warp::path(api_path).and(warp::path("login")).and(rufs_warp_with_rufs(rufs.clone())).and(warp::body::json()).and(warp::addr::remote()).and_then(|rufs: Arc<Mutex<RufsMicroService<'static>>>, login_request: LoginRequest, remote: Option<std::net::SocketAddr>| {
        handle_login(rufs, login_request, remote, authenticator)
    });

    async fn wasm_ws_process_warp(headers: HeaderMap, obj_in: Value) -> Result<impl Reply, Infallible> {
        let token_raw = warp_try!(warp_try!(headers.get("Authorization").ok_or("Missing header Authorization")).to_str());
        let ret = warp_try!(wasm_ws_process(token_raw, obj_in).await);
        Ok(Box::new(warp::reply::json(&ret)))
    }

    let route_wasm_ws_process = warp::path("wasm_ws").and(warp::path("process")).and(warp::header::headers_cloned()).and(warp::body::json()).and_then(wasm_ws_process_warp);

    let routes = route_login.or(route_wasm_login).or(route_wasm_ws_process).or(route_websocket).or(route_api_put).or(route_api_post).or(route_api_get_delete).or(route_api_list_all);
    routes
}

const RUFS_MICRO_SERVICE_OPENAPI_STR: &str = r##"{
    "openapi": "3.0.3",
	"info": {
		"title": "rufs-base-es6 openapi genetator",
		"version": "1.0.2"
	},
    "paths": {},
	"components": {
		"schemas": {
			"rufsGroupOwner": {
				"properties": {
					"name": {"type": "string", "nullable": false}
				},
				"x-primaryKeys": ["name"]
			},
			"rufsUser": {
				"properties": {
					"rufsGroupOwner": {"type": "string", "nullable": false, "x-$ref": "#/components/schemas/rufsGroupOwner"},
					"name":           {"type": "string", "maxLength": 32, "nullable": false},
					"password":       {"type": "string", "nullable": false},
					"path":           {"type": "string"},
					"roles":          {"type": "array", "default": "[]", "items": {"properties": {"path": {"type": "string", "default": ""}, "mask": {"type": "integer", "default": 0, "x-flags": ["get","post","put","delete","query"]}}}},
					"routes":         {"type": "array", "default": "[]", "items": {"properties": {"path": {"type": "string"}, "controller": {"type": "string"}, "templateUrl": {"type": "string"}}}},
					"menu":           {"type": "array", "default": "[]", "items": {"properties": {"group": {"type": "string", "default": "action"}, "label": {"type": "string"}, "path": {"type": "string", "default": "service/action?filter={}&aggregate={}"}}}}
				},
				"x-primaryKeys": ["rufsGroupOwner", "name"],
				"x-uniqueKeys":  {}
			},
			"rufsGroup": {
				"properties": {
					"name": {"type": "string"}
				},
				"x-primaryKeys": ["name"]
			}
		}
	}
}"##;
/*
			"rufsGroupUser": {
				"properties": {
					"rufsUser":  {"type": "string", "nullable": false, "x-$ref": "#/components/schemas/rufsUser"},
					"rufsGroup": {"type": "string", "nullable": false, "x-$ref": "#/components/schemas/rufsGroup"},
					"rufsGroupOwner": {"type": "string", "nullable": false, "x-$ref": "#/components/schemas/rufsGroupOwner"}
				},
				"x-primaryKeys": ["rufsUser", "rufsGroup", "rufsGroupOwner"],
				"x-uniqueKeys":  {}
			}
*/

const DEFAULT_GROUP_OWNER_ADMIN_STR: &str = r#"{"name": "admin"}"#;

const DEFAULT_USER_ADMIN_STR: &str = r#"{
    "name": "admin",
    "rufsGroupOwner": "admin",
    "password": "21232f297a57a5a743894a0e4a801fc3",
    "path": "rufs_user/search",
    "menu": [],
    "roles": [
        {
            "mask": 31,
            "path": "/rufs_group_owner"
        },
        {
            "mask": 31,
            "path": "/rufs_user"
        },
        {
            "mask": 31,
            "path": "/rufs_group"
        }
    ],
    "routes": []
}"#;
/*
        {
            "mask": 31,
            "path": "/rufs_group_user"
        }
*/
