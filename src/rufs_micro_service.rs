
use std::{collections::HashMap, fs, path::Path, sync::{RwLock, Arc}};
use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::{Value,json};
use openapiv3::{OpenAPI,SecurityRequirement};
use jsonwebtoken::{encode, EncodingKey, Header};
use anyhow::Context;
use async_std::path::PathBuf;
use async_trait::async_trait;

use crate::{db_adapter_file::DbAdapterFile,db_adapter_postgres::DbAdapterPostgres,entity_manager::EntityManager,openapi::{FillOpenAPIOptions, RufsOpenAPI, Role}};

#[derive(Deserialize, Serialize, Default)]
#[serde(rename_all = "camelCase")]
struct RufsGroupOwner {
    id: u64,
    name: String,
}

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
#[serde(rename_all = "camelCase")]
struct RufsUserPublic {
    routes: Box<[Route]>,
    menu: Box<[MenuItem]>,
    path: String,
}

#[derive(Deserialize, Serialize, Default)]
#[serde(default)]
#[serde(rename_all = "camelCase")]
struct RufsUser {
    //user_proteced: RufsUserProteced,
    id: u64,
    name: String,
    rufs_group_owner: u64,
    //groups:         Box<[u64]>,
    roles: Box<[Role]>,
    //user_public: RufsUserPublic,
    routes: Box<[Route]>,
    menu: Box<[MenuItem]>,
    path: String,
    //other
    full_name: String,
    password: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LoginResponse<'a> {
    //token_payload : TokenPayload,
    //user_proteced: RufsUserProteced,
    pub id: u64,
    pub name: String,
    pub rufs_group_owner: u64,
    pub groups: Box<[u64]>,
    pub roles: Box<[Role]>,
    pub ip: String,
    //user_public: RufsUserPublic,
    routes: Box<[Route]>,
    menu: Box<[MenuItem]>,
    pub path: String,
    pub jwt_header: String,
    pub title: String,
    pub openapi: &'a OpenAPI,
}

#[derive(Debug, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct Claims {
    sub: String,
    exp: usize,
    id: u64,
    pub name: String,
    pub rufs_group_owner: u64,
    pub groups: Box<[u64]>,
    pub roles: Box<[Role]>,
    ip: String,
}

#[derive(serde::Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct LoginRequest {
    pub user: String,
    pub password: String,
}

#[async_trait]
pub trait Authenticator {
    async fn authenticate_user(&self, user_name: &str, user_password: &str, remote_addr: &str) -> Result<LoginResponse, Box<dyn std::error::Error>>;
}

#[derive(Clone)]
pub struct RufsParams {
    pub app_name: String,
    pub port: u16,
    pub api_path: String,
    pub request_body_content_type: String,
    pub openapi_file_name : String,
}

impl Default for RufsParams {
    fn default() -> Self {
        Self {
            port: 8080,
            api_path: "rest".to_string(),
            app_name: "base".to_string(),
            request_body_content_type: "application/json".to_string(),
            openapi_file_name: "".to_string(),
        }
    }
}

#[derive(Clone)]
pub struct RufsMicroService<'a> {
    pub params: RufsParams,
    pub openapi: OpenAPI,
    pub entity_manager: DbAdapterPostgres<'a>,
    pub db_adapter_file: DbAdapterFile<'a>,
    pub ws_server_connections_tokens : Arc<RwLock<HashMap<String, Claims>>>,
    pub watcher: &'static Box<dyn DataViewWatch>,
    #[cfg(feature = "tide")]
    pub ws_server_connections_tide : Arc<RwLock<HashMap<String, tide_websockets::WebSocketConnection>>>,
    #[cfg(feature = "warp")]
    pub ws_server_connections_warp : Arc<RwLock<HashMap<String, futures_util::stream::SplitSink<warp::ws::WebSocket, warp::ws::Message>>>>,
}

impl RufsMicroService<'_> {
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
    
    pub fn store_open_api(&self, file_name :&str) -> Result<(), Box<dyn std::error::Error>> {
        let file_name = if file_name.is_empty() {
            &self.params.openapi_file_name
        } else {
            file_name
        };

        let contents = serde_json::to_string_pretty(&self.openapi)?;
        std::fs::write(file_name, contents)?;
        Ok(())
    }

    pub async fn connect<'a>(db_uri: &str, rufs_tables_in_db: bool, migration_path: &str, params: RufsParams, watcher: &'static Box<dyn DataViewWatch>) -> Result<RufsMicroService<'a>, Box<dyn std::error::Error>> {
        fn load_file_tables(rms :&mut RufsMicroService) -> Result<(), Box<dyn std::error::Error>> {
            fn load_table(rms: &mut RufsMicroService, name: &str, default_rows: &serde_json::Value) -> Result<(), Box<dyn std::error::Error>> {
                if rms.db_adapter_file.have_table(&name) {
                    return Ok(());
                }
    
                rms.db_adapter_file.load(name, default_rows)
            }
    
            //RequestFilterUpdateRufsServices(rms.fileDbAdapter, rms.openapi)
            let empty_list = serde_json::Value::default();
            load_table(rms, "rufsGroup", &empty_list)?;
            load_table(rms, "rufsGroupUser", &empty_list)?;
            let item: serde_json::Value = serde_json::from_str(DEFAULT_GROUP_OWNER_ADMIN_STR).unwrap();
            let list = serde_json::json!([item]);
            load_table(rms, "rufsGroupOwner", &list)?;
            let item: serde_json::Value = serde_json::from_str(DEFAULT_USER_ADMIN_STR).unwrap();
            let list = serde_json::json!([item]);
            load_table(rms, "rufsUser", &list)?;
            Ok(())
        }
    
        async fn create_rufs_tables(rms: &RufsMicroService<'_>, openapi_rufs: &OpenAPI) -> Result<(), Box<dyn std::error::Error>> {
            for name in ["rufsGroupOwner", "rufsUser", "rufsGroup", "rufsGroupUser"] {
                if rms.openapi.components.as_ref().unwrap().schemas.get(name).is_none() {
                    println!("don't matched schema {}, existents :\n{:?}", name, rms.openapi.components.as_ref().unwrap().schemas.keys());
                    let schema = openapi_rufs.components.as_ref().unwrap().schemas.get(name).unwrap().as_item().unwrap();
                    rms.entity_manager.create_table(name, schema).await?;
                }
            }

            let default_group_owner_admin: serde_json::Value = serde_json::from_str(DEFAULT_GROUP_OWNER_ADMIN_STR).unwrap();
            let default_user_admin: serde_json::Value = serde_json::from_str(DEFAULT_USER_ADMIN_STR).unwrap();

            if rms.entity_manager.find_one(openapi_rufs, "rufsGroupOwner", &json!({"name": "admin"})).await.is_none() {
                rms.entity_manager.insert(openapi_rufs, "rufsGroupOwner", &default_group_owner_admin).await?;
            }

            if rms.entity_manager.find_one(openapi_rufs, "rufsUser", &json!({"name": "admin"})).await.is_none() {
                rms.entity_manager.insert(openapi_rufs, "rufsUser", &default_user_admin).await?;
            }

            Ok(())
        }

        async fn exec_migrations(rms: &mut RufsMicroService<'_>, migration_path: &str) -> Result<(), Box<dyn std::error::Error>> {
            fn get_version(name: &str) -> Result<usize, Box<dyn std::error::Error>> {
                let reg_exp = Regex::new(r"(\d{1,3})\.(\d{1,3})\.(\d{1,3})").unwrap();
                let reg_exp_result = reg_exp.captures(name).unwrap();

                if reg_exp_result.len() != 4 {
                    return Err(format!("Missing valid version in name {}", name))?;
                }

                let str_version = format!(
                    "{:03}{:03}{:03}",
                    reg_exp_result.get(1).unwrap().as_str().parse::<usize>().unwrap(),
                    reg_exp_result.get(2).unwrap().as_str().parse::<usize>().unwrap(),
                    reg_exp_result.get(3).unwrap().as_str().parse::<usize>().unwrap()
                );

                println!("str_version {}", str_version);
                Ok(str_version.parse().unwrap())
            }

            async fn migrate(rms: &mut RufsMicroService<'_>, migration_path: &str, file_name: &str) -> Result<(), Box<dyn std::error::Error>> {
                println!("Migrating to version {}...", file_name);
                let text = fs::read_to_string(PathBuf::from(migration_path).join(file_name))?;

                for sql in text.split("--split") {
                    rms.entity_manager.exec(sql).await?;
                }

                let new_version = get_version(file_name)?;
                rms.openapi.info.version = format!("{}.{}.{}", ((new_version / 1000) / 1000) % 1000, (new_version / 1000) % 1000, new_version % 1000);
                println!("... Migrated version {}", file_name);
                Ok(())
            }

            if Path::new(migration_path).exists() == false {
                return Ok(());
            }

            let old_version = get_version(&rms.openapi.info.version)?;

            let files = fs::read_dir(migration_path).context("Broken migration path.")?;
            let mut list: Vec<String> = vec![];

            for file_info in files {
                let path = file_info.unwrap().file_name().into_string().unwrap();
                let version = get_version(&path)?;

                if version > old_version {
                    list.push(path);
                }
            }

            list.sort_by(|a, b| {
                let version_i = get_version(a).unwrap();
                let version_j = get_version(b).unwrap();
                return version_i.cmp(&version_j);
            });

            for file_name in &list {
                migrate(rms, migration_path, file_name).await.unwrap();
            }

            Ok(())
        }

        let mut rufs = RufsMicroService {
            params, 
            watcher,
            openapi: Default::default(),
            entity_manager: DbAdapterPostgres::default(),
            db_adapter_file: DbAdapterFile::default(),
            ws_server_connections_tokens: Arc::default(),
            #[cfg(feature = "tide")]
            ws_server_connections_tide: Arc::default(),
            #[cfg(feature = "warp")]
            ws_server_connections_warp: Arc::default(),
        };
    
        rufs.load_open_api()?;
        rufs.entity_manager.connect(db_uri).await?;
        //self.entity_manager.UpdateOpenAPI(self.openapi, FillOpenAPIOptions{requestBodyContentType: self.requestBodyContentType};
        let openapi_rufs = serde_json::from_str::<OpenAPI>(RUFS_MICRO_SERVICE_OPENAPI_STR)?;

        if rufs_tables_in_db {
            create_rufs_tables(&rufs, &openapi_rufs).await?;
        }

        exec_migrations(&mut rufs, migration_path).await?;
        //rms.db_adapter_file.openapi = Some(&rms.openapi);
        let mut options = FillOpenAPIOptions::default();
        options.request_body_content_type = rufs.params.request_body_content_type.clone();
        //self.micro_service_server.store_open_api("")?;
        rufs.entity_manager.update_open_api(&mut rufs.openapi, &mut options).await?;
        let mut options = FillOpenAPIOptions::default();
        options.security = SecurityRequirement::from([("jwt".to_string(), vec![])]);
        options.schemas = openapi_rufs.components.context("missing section components")?.schemas.clone();
        options.request_body_content_type = rufs.params.request_body_content_type.clone();
        rufs.openapi.fill(&mut options)?;
        rufs.store_open_api("")?;

        if rufs_tables_in_db == false {
            load_file_tables(&mut rufs)?;
        }

        Ok(rufs)
    }

}

#[async_trait]
impl Authenticator for RufsMicroService<'_> {

    async fn authenticate_user(&self, user_name: &str, user_password: &str, remote_addr: &str) -> Result<LoginResponse, Box<dyn std::error::Error>> {
        let entity_manager = if self.db_adapter_file.have_table("rufsUser") {
            &self.db_adapter_file as &(dyn EntityManager + Sync + Send)
        } else {
            &self.entity_manager as &(dyn EntityManager + Sync + Send)
        };

        let user = entity_manager.find_one(&self.openapi, "rufsUser", &json!({ "name": user_name })).await.context("Fail to find user.")?;
        let user = RufsUser::deserialize(*user)?;

        if user.password.len() > 0 && user.password != user_password {
            return Err("Don't match user and password.")?;
        }

        let list_in = entity_manager.find(&self.openapi, "rufsGroupUser", &json!({"rufsUser": user.id}), &vec![]).await;
        let mut list_out: Vec<u64> = vec![];

        for item in list_in {
            println!("[RufsMicroService.authenticate_user] rufsGroupUser : {}", item);
            list_out.push(item.get("rufsGroup").unwrap().as_u64().unwrap());
        }

        let groups = list_out.into_boxed_slice();
        //let user_proteced = RufsUserProteced { id: user.id, name: user.name.clone(), group_owner: user.group_owner, groups: user.groups, roles: user.roles};
        //let token_payload = TokenPayload{user_proteced, ip: remote_addr.clone()};
        //let user_public = RufsUserPublic{ routes: user.routes, menu: user.menu, path: user.path };
        let claims = Claims {
            sub: "".to_string(),
            exp: 10000000000,
            id: user.id,
            name: user.name,
            rufs_group_owner: user.rufs_group_owner,
            groups,
            roles: user.roles,
            ip: remote_addr.to_string(),
        };
        let secret = std::env::var("RUFS_JWT_SECRET").unwrap_or("123456".to_string());
        let jwt_header = encode(&Header::default(), &claims, &EncodingKey::from_secret(secret.as_ref()))?;
        let login_response = LoginResponse {
            id: user.id,
            name: claims.name.clone(),
            rufs_group_owner: user.rufs_group_owner,
            groups: claims.groups,
            roles: claims.roles,
            ip: claims.ip.clone(),
            routes: user.routes,
            menu: user.menu,
            path: user.path.clone(),
            jwt_header,
            title: claims.name,
            openapi: &self.openapi,
        };
        Ok(login_response)
    }

}

use crate::client::DataViewWatch;

lazy_static::lazy_static! {
    static ref DATA_VIEW_MANAGER_MAP: tokio::sync::Mutex<std::collections::HashMap<String, crate::client::DataViewManager<'static>>>  = {
        let data_view_manager_map = std::collections::HashMap::new();
        tokio::sync::Mutex::new(data_view_manager_map)
    }; 
}

async fn wasm_login(rms: &RufsMicroService<'_>, data_in: Value) -> Result<Value, Box<dyn std::error::Error>> {
    let mut data_view_manager_map = DATA_VIEW_MANAGER_MAP.lock().await;
    let path = format!("http://127.0.0.1:{}", rms.params.port);
    let mut data_view_manager = crate::client::DataViewManager::new(&path, rms.watcher);
    let data_out = data_view_manager.login(data_in).await?;
    data_view_manager_map.insert(data_view_manager.server_connection.login_response.jwt_header.clone(), data_view_manager);
    Ok(data_out.into())
}

async fn wasm_process(token_raw: &str, data_in: Value) -> Result<Value, Box<dyn std::error::Error>> {
    let authorization_header_prefix = "Bearer ";

    let jwt = if token_raw.starts_with(authorization_header_prefix) {
        &token_raw[authorization_header_prefix.len()..]
    } else {
        return None.context("broken token")?;
    };

    let mut data_view_manager_map = DATA_VIEW_MANAGER_MAP.lock().await;
    let data_view_manager = data_view_manager_map.get_mut(jwt).context("Missing session")?;
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
                println!("[RufsMicroService.handle.login.authenticate_user] : {}", error);
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
        print!("\n\ncurl -X '{}' {} -H 'Authorization: {}'", method, request.url(), auth);
    
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

        let data_out = match wasm_login(rms, data_in).await {
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

        let data_out = match wasm_process(token_raw, data_in).await {
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
pub async fn rufs_warp(rufs: RufsMicroService<'static>) -> impl warp::Filter<Extract = (impl warp::Reply,), Error = warp::Rejection> + Clone {
    use std::{sync::Mutex, convert::Infallible};
    use jsonwebtoken::{decode, DecodingKey, Validation};
    use futures_util::StreamExt;
    use warp::Reply;
    use warp::http::{Method, HeaderMap, StatusCode};
    use warp::path::FullPath;
    use warp::Filter;
    use warp::ws::WebSocket;

    use crate::request_filter::RequestFilter;

    let api_path = rufs.params.api_path.clone();
    let rufs = Arc::new(Mutex::new(rufs));

    fn with_rufs(rufs: Arc<Mutex<RufsMicroService<'static>>>) -> impl Filter<Extract = (Arc<Mutex<RufsMicroService<'static>>>,), Error = Infallible> + Clone {
        warp::any().map(move || rufs.clone())
    }

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

    async fn handle_api(rufs: Arc<Mutex<RufsMicroService<'static>>>, method: Method, path: FullPath, headers: HeaderMap, query: String, obj_in: Value) -> Result<impl Reply, Infallible> {
        let method = method.to_string().to_lowercase();
        let path = path.as_str();
        let header = warp_try!(headers.get("Authorization").context("400-Missing Authorization header."));
        let auth = warp_try!(header.to_str());

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

        print!("\n\ncurl -X '{}' {} -H 'Authorization: {}'", method, path, auth);
        let rufs = &rufs.lock().unwrap().to_owned();
        let mut rf = RequestFilter::new(rufs, path, query, &method, obj_in).unwrap();

        if warp_try!(rf.check_authorization::<RufsMicroService>(&headers_out).await) == false {
            warp_try!(Err("401-Unauthorized."))
        }

        let ret = warp_try!(rf.process_request().await);
        let ret = warp::reply::json(&ret);
        Ok(Box::new(ret))
    }
    
    let route_api_put = warp::path(api_path.clone()).
        and(with_rufs(rufs.clone())).and(warp::method()).and(warp::path::full()).and(warp::header::headers_cloned()).
        and(warp::query::raw()).and(warp::body::json()).and_then(handle_api);

    async fn handle_api_post(rufs: Arc<Mutex<RufsMicroService<'static>>>, method: Method, path: FullPath, headers: HeaderMap, obj_in: Value) -> Result<impl Reply, Infallible> {
        handle_api(rufs, method, path, headers, String::new(), obj_in).await
    }

    let route_api_post = warp::path(api_path.clone()).
        and(with_rufs(rufs.clone())).and(warp::method()).and(warp::path::full()).and(warp::header::headers_cloned()).and(warp::body::json()).
        and_then(handle_api_post);
    
    async fn handle_api_get_delete(rufs: Arc<Mutex<RufsMicroService<'static>>>, method: Method, path: FullPath, headers: HeaderMap, query: String) -> Result<impl Reply, Infallible> {
        handle_api(rufs, method, path, headers, query, json!({})).await
    }

    let route_api_get_delete = warp::path(api_path.clone()).
        and(with_rufs(rufs.clone())).and(warp::method()).and(warp::path::full()).and(warp::header::headers_cloned()).and(warp::query::raw()).
        and_then(handle_api_get_delete);
    
    async fn handle_api_list_all(rufs: Arc<Mutex<RufsMicroService<'static>>>, method: Method, path: FullPath, headers: HeaderMap) -> Result<impl Reply, Infallible> {
        handle_api(rufs, method, path, headers, String::new(), json!({})).await
    }

    let route_api_list_all = warp::path(api_path.clone()).
        and(with_rufs(rufs.clone())).and(warp::method()).and(warp::path::full()).and(warp::header::headers_cloned()).
        and_then(handle_api_list_all);
    
    async fn handle_ws(rufs: Arc<Mutex<RufsMicroService<'static>>>, ws: warp::ws::Ws) -> Result<impl Reply, Infallible> {
        async fn user_connected(ws: WebSocket, rufs: Arc<Mutex<RufsMicroService<'static>>>) {
            let (user_ws_tx, mut user_ws_rx) = ws.split();
            
            if let Some(Ok(msg)) = user_ws_rx.next().await {
                if let Ok(token) = msg.to_str() {
                    if let Ok(rufs) = rufs.lock() {
                        let secret = std::env::var("RUFS_JWT_SECRET").unwrap_or("123456".to_string());

                        if let Ok(token_data) = decode::<Claims>(&token, &DecodingKey::from_secret(secret.as_ref()), &Validation::default()) {
                            rufs.ws_server_connections_warp.write().unwrap().insert(token.to_string(), user_ws_tx);
                            rufs.ws_server_connections_tokens.write().unwrap().insert(token.to_string(), token_data.claims);
                        }
                    }
                }
            }
        }

        let res = ws.on_upgrade(move |socket| user_connected(socket, rufs));
        Ok(res)
    }

    let route_websocket = warp::path("websocket").and(with_rufs(rufs.clone())).and(warp::ws()).and_then(handle_ws);

    async fn wasm_login_warp(rufs: Arc<Mutex<RufsMicroService<'static>>>, data_in: Value, _remote: Option<std::net::SocketAddr>) -> Result<impl Reply, Infallible> {
        let rufs = &rufs.lock().unwrap().to_owned();
        let ret = warp_try!(wasm_login(rufs, data_in).await);
        Ok(Box::new(warp::reply::json(&ret)))
    }
        
    let route_wasm_login = warp::path("wasm_ws").and(warp::path("login")).and(with_rufs(rufs.clone())).and(warp::body::json()).and(warp::addr::remote()).and_then(wasm_login_warp);

    async fn handle_login(rufs: Arc<Mutex<RufsMicroService<'static>>>, login_request: LoginRequest, remote: Option<std::net::SocketAddr>) -> Result<impl Reply, Infallible> {
        let remote = warp_try!(remote.context("400-Missing remote address."));
        let rufs = &rufs.lock().unwrap().to_owned();
        let ret = warp_try!(rufs.authenticate_user(&login_request.user, &login_request.password, &remote.to_string()).await);
        Ok(Box::new(warp::reply::json(&ret)))
    }
    
    let route_login = warp::path(api_path).and(warp::path("login")).and(with_rufs(rufs.clone())).and(warp::body::json()).and(warp::addr::remote()).and_then(handle_login);
    
    async fn wasm_process_warp(headers: HeaderMap, obj_in: Value) -> Result<impl Reply, Infallible> {
        let token_raw = warp_try!(warp_try!(headers.get("Authorization").context("Missing header Authorization")).to_str());
        let ret = warp_try!(wasm_process(token_raw, obj_in).await);
        Ok(Box::new(warp::reply::json(&ret)))
    }
        
    let route_wasm_process = warp::path("wasm_ws").and(warp::path("process")).and(warp::header::headers_cloned()).and(warp::body::json()).and_then(wasm_process_warp);

    let routes = route_login.or(route_wasm_login).or(route_wasm_process).or(route_websocket).or(route_api_put).or(route_api_post).or(route_api_get_delete).or(route_api_list_all);
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
					"id":   {"type": "integer", "x-identityGeneration": "BY DEFAULT"},
					"name": {"type": "string", "nullable": false, "unique": true}
				},
				"x-primaryKeys": ["id"]
			},
			"rufsUser": {
				"properties": {
					"id":             {"type": "integer", "x-identityGeneration": "BY DEFAULT"},
					"rufsGroupOwner": {"type": "integer", "nullable": false, "x-$ref": "#/components/schemas/rufsGroupOwner"},
					"name":           {"type": "string", "maxLength": 32, "nullable": false, "unique": true},
					"password":       {"type": "string", "nullable": false},
					"path":           {"type": "string"},
					"roles":          {"type": "array", "items": {"properties": {"path": {"type": "string", "default": ""}, "mask": {"type": "integer", "default": 0, "x-flags": ["get","post","put","delete","query"]}}}},
					"routes":         {"type": "array", "items": {"properties": {"path": {"type": "string"}, "controller": {"type": "string"}, "templateUrl": {"type": "string"}}}},
					"menu":           {"type": "array", "items": {"properties": {"group": {"type": "string", "default": "action"}, "label": {"type": "string"}, "path": {"type": "string", "default": "service/action?filter={}&aggregate={}"}}}}
				},
				"x-primaryKeys": ["id"],
				"x-uniqueKeys":  {}
			},
			"rufsGroup": {
				"properties": {
					"id":   {"type": "integer", "x-identityGeneration": "BY DEFAULT"},
					"name": {"type": "string", "nullable": false, "unique": true}
				},
				"x-primaryKeys": ["id"]
			},
			"rufsGroupUser": {
				"properties": {
					"rufsUser":  {"type": "integer", "nullable": false, "x-$ref": "#/components/schemas/rufsUser"},
					"rufsGroup": {"type": "integer", "nullable": false, "x-$ref": "#/components/schemas/rufsGroup"}
				},
				"x-primaryKeys": ["rufsUser", "rufsGroup"],
				"x-uniqueKeys":  {}
			}
		}
	}
}"##;


const DEFAULT_GROUP_OWNER_ADMIN_STR: &str = r#"{"name": "admin"}"#;


const DEFAULT_USER_ADMIN_STR: &str = r#"{
    "name": "admin",
    "rufsGroupOwner": 1,
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
        },
        {
            "mask": 31,
            "path": "/rufs_group_user"
        }
    ],
    "routes": [
        {
            "controller": "OpenApiOperationObjectController",
            "path": "/app/rufs_service/:action"
        },
        {
            "controller": "UserController",
            "path": "/app/rufs_user/:action"
        }
    ]
}"#;
