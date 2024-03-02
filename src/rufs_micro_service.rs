#[cfg(not(target_arch = "wasm32"))]
#[cfg(feature = "http_server")]
use std::{collections::HashMap, fs, path::Path, sync::{RwLock, Arc}};

#[cfg(not(target_arch = "wasm32"))]
use anyhow::Context;
#[cfg(not(target_arch = "wasm32"))]
#[cfg(feature = "http_server")]
use async_std::path::PathBuf;
#[cfg(not(target_arch = "wasm32"))]
#[cfg(feature = "http_server")]
use jsonwebtoken::{encode, EncodingKey, Header};

use openapiv3::{OpenAPI};
#[cfg(not(target_arch = "wasm32"))]
use openapiv3::{SecurityRequirement};
#[cfg(not(target_arch = "wasm32"))]
use regex::Regex;
use serde::{Deserialize, Serialize};
#[cfg(not(target_arch = "wasm32"))]
use serde_json::json;

#[cfg(not(target_arch = "wasm32"))]
#[cfg(feature = "tide")]
use tide::{Error, StatusCode};

#[cfg(not(target_arch = "wasm32"))]
#[cfg(feature = "tide")]
use tide_websockets::WebSocketConnection;

use crate::openapi::Role;
#[cfg(not(target_arch = "wasm32"))]
#[cfg(feature = "http_server")]
use crate::{
    db_adapter_file::DbAdapterFile,
    db_adapter_postgres::DbAdapterPostgres,
    entity_manager::EntityManager,
    micro_service_server::{IMicroServiceServer, MicroServiceServer},
    openapi::{FillOpenAPIOptions, RufsOpenAPI},
};

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

/*
type IRufsMicroService interface {
    IMicroServiceServer
    LoadFileTables() error
}
*/
#[cfg(not(target_arch = "wasm32"))]
#[cfg(feature = "tide")]
#[derive(Clone)]
pub struct RufsMicroService<'a> {
    pub micro_service_server: MicroServiceServer,
    /*
    dbConfig                  *DbConfig
    */
    pub check_rufs_tables: bool,
    pub migration_path: String,
    pub static_paths: Vec<String>,
    pub entity_manager: DbAdapterPostgres<'a>,
    pub db_adapter_file: DbAdapterFile<'a>,
    pub ws_server_connections : Arc<RwLock<HashMap<String, WebSocketConnection>>>,
    pub ws_server_connections_tokens : Arc<RwLock<HashMap<String, Claims>>>,
    pub watcher: &'static Box<dyn DataViewWatch>
}

/*

func (rms *RufsMicroService) OnRequest(req *http.Request) Response {
    if strings.HasSuffix(req.URL.Path, "/login") {
        loginRequest := map[string]string{}
        err := json.NewDecoder(req.Body).Decode(&loginRequest)

        if err != nil {
            return ResponseUnauthorized(fmt.Sprint(err))
        }

        userName, ok := loginRequest["user"]

        if !ok {
            return ResponseBadRequest(fmt.Sprint("[RufsMicroService.OnRequest.login] missing field 'user'"))
        }

        password, ok := loginRequest["password"]

        if !ok {
            return ResponseBadRequest(fmt.Sprint("[RufsMicroService.OnRequest.login] missing field 'password'"))
        }

        if loginResponse, err := rms.authenticateUser(userName, password, req.RemoteAddr); err == nil {
            if userName == "admin" {
                loginResponse.Openapi = rms.openapi
            } else {
                loginResponse.Openapi = rms.openapi
            }

            token := jwt.New(jwt.SigningMethodHS256)
            token.Claims = &RufsClaims{&jwt.StandardClaims{ExpiresAt: time.Now().Add(time.Minute * 60 * 8).Unix()}, loginResponse.TokenPayload}
            jwtSecret := os.Getenv("RUFS_JWT_SECRET")

            if jwtSecret == "" {
                jwtSecret = "123456"
            }

            loginResponse.JwtHeader, err = token.SignedString([]byte(jwtSecret))
            return ResponseOk(loginResponse)
        } else {
            return ResponseUnauthorized(fmt.Sprint(err))
        }
    } else {
        rf, err := RequestFilterInitialize(req, rms)

        if err != nil {
            return ResponseBadRequest(fmt.Sprintf("[RufsMicroService.OnRequest] : %s", err))
        }

        if access, err := rf.CheckAuthorization(req); err != nil {
            return ResponseBadRequest(fmt.Sprintf("[RufsMicroService.OnRequest.CheckAuthorization] : %s", err))
        } else if !access {
            return ResponseUnauthorized("Explicit Unauthorized")
        }

        return rf.ProcessRequest()
    }
}

func (rms *RufsMicroService) OnWsMessageFromClient(connection *websocket.Conn, tokenString string) {
    rms.MicroServiceServer.OnWsMessageFromClient(connection, tokenString)

    token, err := jwt.ParseWithClaims(tokenString, &RufsClaims{}, func(token *jwt.Token) (interface{}, error) {
        if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
            return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
        }

        jwtSecret := os.Getenv("RUFS_JWT_SECRET")

        if jwtSecret == "" {
            jwtSecret = "123456"
        }

        hmacSampleSecret := []byte(jwtSecret)
        return hmacSampleSecret, nil
    })

    if claims, ok := token.Claims.(*RufsClaims); ok && token.Valid {
        rms.wsServerConnections[tokenString] = connection
        rms.wsServerConnectionsTokens[tokenString] = claims
        log.Printf("[MicroServiceServer.onWsMessageFromClient] Ok")
    } else {
        fmt.Println(err)
    }
}
*/
#[cfg(not(target_arch = "wasm32"))]
#[cfg(feature = "tide")]
impl RufsMicroService<'_> {
    pub async fn connect(&mut self, db_uri: &str) -> Result<(), Box<dyn std::error::Error>> {
        fn load_file_tables(rms :&mut RufsMicroService) -> Result<(), Error> {
            fn load_table(rms: &mut RufsMicroService, name: &str, default_rows: &serde_json::Value) -> Result<(), Error> {
                if rms.db_adapter_file.have_table(&name) {
                    return Ok(());
                }
    
                rms.db_adapter_file.load(name, default_rows).or(Err(Error::from_str(500, "")))
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
            if !rms.check_rufs_tables {
                return Ok(());
            }

            for name in ["rufsGroupOwner", "rufsUser", "rufsGroup", "rufsGroupUser"] {
                if rms.micro_service_server.openapi.components.as_ref().unwrap().schemas.get(name).is_none() {
                    println!("don't matched schema {}, existents :\n{:?}", name, rms.micro_service_server.openapi.components.as_ref().unwrap().schemas.keys());
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

        async fn exec_migrations(rms: &mut RufsMicroService<'_>) -> Result<(), Error> {
            fn get_version(name: &str) -> Result<usize, Error> {
                let reg_exp = Regex::new(r"(\d{1,3})\.(\d{1,3})\.(\d{1,3})").unwrap();
                let reg_exp_result = reg_exp.captures(name).unwrap();

                if reg_exp_result.len() != 4 {
                    return Err(Error::from_str(500, format!("Missing valid version in name {}", name)));
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

            async fn migrate(rms: &mut RufsMicroService<'_>, file_name: &str) -> Result<(), Error> {
                println!("Migrating to version {}...", file_name);
                let text = fs::read_to_string(PathBuf::from(rms.migration_path.clone()).join(file_name))?;

                for sql in text.split("--split") {
                    if let Err(error) = rms.entity_manager.exec(sql).await {
                        return Err(tide::Error::from_str(500, format!("{}", error)));
                    }
                }

                let new_version = get_version(file_name)?;
                rms.micro_service_server.openapi.info.version = format!("{}.{}.{}", ((new_version / 1000) / 1000) % 1000, (new_version / 1000) % 1000, new_version % 1000);
                println!("... Migrated version {}", file_name);
                Ok(())
            }

            if Path::new(&rms.migration_path).exists() == false {
                return Ok(());
            }

            let old_version = get_version(&rms.micro_service_server.openapi.info.version)?;

            let files = fs::read_dir(rms.migration_path.clone()).unwrap();
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

            for file_name in list {
                migrate(rms, &file_name).await.unwrap();
            }

            Ok(())
        }

        self.micro_service_server.connect()?;
        self.entity_manager.connect(db_uri).await?;
        //self.entity_manager.UpdateOpenAPI(self.openapi, FillOpenAPIOptions{requestBodyContentType: self.requestBodyContentType};
        let openapi_rufs = serde_json::from_str::<OpenAPI>(RUFS_MICRO_SERVICE_OPENAPI_STR)?;
        create_rufs_tables(self, &openapi_rufs).await?;
        exec_migrations(self).await?;
        //rms.db_adapter_file.openapi = Some(&rms.micro_service_server.openapi);
        let mut options = FillOpenAPIOptions::default();
        options.request_body_content_type = self.micro_service_server.request_body_content_type.clone();
        //self.micro_service_server.store_open_api("")?;
        self.entity_manager.update_open_api(&mut self.micro_service_server.openapi, &mut options).await?;
        let mut options = FillOpenAPIOptions::default();
        options.security = SecurityRequirement::from([("jwt".to_string(), vec![])]);
        options.schemas = openapi_rufs.components.context("missing section components")?.schemas.clone();
        options.request_body_content_type = self.micro_service_server.request_body_content_type.clone();
        self.micro_service_server.openapi.fill(&mut options)?;
        self.micro_service_server.store_open_api("")?;

        if self.check_rufs_tables == false {
            load_file_tables(self)?;
        }

        Ok(())
    }
}

#[cfg(not(target_arch = "wasm32"))]
#[cfg(feature = "tide")]
#[tide::utils::async_trait]
impl IMicroServiceServer for RufsMicroService<'_> {

    async fn authenticate_user(&self, user_name: &str, user_password: &str, remote_addr: &str) -> Result<LoginResponse, Error> {
        let entity_manager = if self.db_adapter_file.have_table("rufsUser") {
            &self.db_adapter_file as &(dyn EntityManager + Sync + Send)
        } else {
            &self.entity_manager as &(dyn EntityManager + Sync + Send)
        };

        let user = match entity_manager.find_one(&self.micro_service_server.openapi, "rufsUser", &json!({ "name": user_name })).await {
            Some(value) => {
                match RufsUser::deserialize(*value) {
                    Ok(user) => user,
                    Err(error) => return Err(Error::from_str(StatusCode::InternalServerError, format!("fail to parse struct from json : {}", error))),
                }
            },
            None => return Err(Error::from_str(StatusCode::InternalServerError, "fail to find user")),
        };

        if user.password.len() > 0 && user.password != user_password {
            return Err(Error::from_str(StatusCode::Unauthorized, "Don't match user and password."));
        }

        let list_in = entity_manager.find(&self.micro_service_server.openapi, "rufsGroupUser", &json!({"rufsUser": user.id}), &vec![]).await;
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
            openapi: &self.micro_service_server.openapi,
        };
        Ok(login_response)
    }

}

#[cfg(not(target_arch = "wasm32"))]
#[cfg(feature = "tide")]
use crate::client::DataViewWatch;

#[cfg(not(target_arch = "wasm32"))]
#[cfg(feature = "tide")]
pub async fn rufs_tide_new(rufs: RufsMicroService<'static>) -> Result<Box<tide::Server<RufsMicroService<'static>>>, Box<dyn std::error::Error>> {
    use jsonwebtoken::{decode, DecodingKey, Validation};
    use serde_json::Value;
    use std::{future::Future, pin::Pin};
    use async_std::path::Path;
    use tide::{Response, Next, Body, http::{mime}};

    use crate::{micro_service_server::LoginRequest, request_filter::RequestFilter, client::DataViewManager};

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
                let mut response = Response::from(error);
                response.set_content_type(mime::PLAIN);
                response.set_body(msg);
                return Ok(response);
            }
        };
    
        Ok(Response::builder(StatusCode::Ok).body(Body::from_json(&login_response)?).build())
    }
    
    async fn handle_api(mut request: tide::Request<RufsMicroService<'_>>) -> tide::Result {
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
        let mut rf = RequestFilter::new(&request, rufs, &method, obj_in).unwrap();
    
        if rf.schema_name == "request" && rf.method == "put" {
          println!("handle_api = {}", rf.schema_name);
        }
    
        let response = match rf.check_authorization(&request).await {
            Ok(true) => rf.process_request().await,
            Ok(false) => Response::builder(StatusCode::Unauthorized).build(),
            Err(err) => tide::Response::builder(StatusCode::BadRequest)
                .body(format!("[RufsMicroService.OnRequest.CheckAuthorization] : {}", err))
                .build(),
        };
    
        Ok(response)
    }
    
    fn static_paths<'a>(request: tide::Request<RufsMicroService<'static>>, next: Next<'a, RufsMicroService<'static>>) -> Pin<Box<dyn Future<Output = tide::Result> + Send + 'a>> {
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
            let api_path = format!("{}/", rufs.micro_service_server.api_path);

            if request.url().path().starts_with(&api_path) {
                return Ok(next.run(request).await);
            }

            let path = request.url().path()[1..].to_string();
    
            let name = if path.ends_with("/") || path.is_empty() {
                path.clone() + &"index.html".to_string()
            } else {
                path.clone()
            };
    
            for folder in &rufs.static_paths {
                let file = Path::new(folder).join(&name);
                //println!("[TideRufsMicroService.handle] folder = {:?}, url_file = {}, file = {:?}", folder, name, file);
    
                if file.exists().await {
                    match tide::Body::from_file(&file).await {
                        Ok(body) => return Ok(Response::builder(StatusCode::Ok).body(body).build()),
                        Err(e) => return Err(e.into()),
                    }
                }
            }
    
            Ok(next.run(request).await)
        })
    }

    let api_path = rufs.micro_service_server.api_path.clone();
    let mut app = Box::new(tide::with_state(rufs));

    app.at("/websocket").get(tide_websockets::WebSocket::new(|request, mut stream| async move {
        while let Some(Ok(tide_websockets::Message::Text(token))) = async_std::stream::StreamExt::next(&mut stream).await {
            let wsc = stream.clone();
            let rufs :&RufsMicroService= request.state();
            rufs.ws_server_connections.write().unwrap().insert(token.clone(), wsc);
            let secret = std::env::var("RUFS_JWT_SECRET").unwrap_or("123456".to_string());
            let token_data = decode::<Claims>(&token, &DecodingKey::from_secret(secret.as_ref()), &Validation::default())?;
            rufs.ws_server_connections_tokens.write().unwrap().insert(token, token_data.claims);
        }

        Ok(())
    }));

    let path_login = format!("/{}/login", &api_path);
    println!("[rufs_tide_new] listening login at {}...", path_login);
    app.at(&path_login).post(handle_login);
    let path_api = format!("/{}/*", &api_path);
    println!("[rufs_tide_new] listening api at {}...", path_api);
    app.at(&path_api).all(handle_api);
    app.with(static_paths);
    
    lazy_static::lazy_static! {
        static ref DATA_VIEW_MANAGER_MAP: tokio::sync::Mutex<std::collections::HashMap<String, DataViewManager<'static>>>  = {
            let data_view_manager_map = std::collections::HashMap::new();
            tokio::sync::Mutex::new(data_view_manager_map)
        }; 
    }

    async fn wasm_login(mut req: tide::Request<RufsMicroService<'_>>) -> tide::Result {
        let data_in = req.body_json::<Value>().await?;
        let mut data_view_manager_map = DATA_VIEW_MANAGER_MAP.lock().await;
        let state = req.state();
        //, data_in.get("path").context("Missing param path")?.as_str().context("Param path is not string")?
        let path = format!("http://127.0.0.1:{}", state.micro_service_server.port);
        let mut data_view_manager = DataViewManager::new(&path, state.watcher);

        let data_out = match data_view_manager.login(data_in).await {
            Ok(data_out) => data_out,
            Err(err) => {
                let mut response = tide::Response::from(err.to_string());
                response.set_status(401);
                return Ok(response);
            }
        };

        data_view_manager_map.insert(data_view_manager.server_connection.login_response.jwt_header.clone(), data_view_manager);
        Ok(data_out.into())
    }
        
    app.at("/wasm_ws/login").post(wasm_login);

    async fn wasm_process(mut req: tide::Request<RufsMicroService<'_>>) -> tide::Result {
        let authorization_header_prefix = "Bearer ";
        let token_raw = req.header("Authorization").context("Missing header Authorization")?.last().as_str();

        let jwt = if token_raw.starts_with(authorization_header_prefix) {
            &token_raw[authorization_header_prefix.len()..]
        } else {
            return None.context("broken token")?;
        };

        let mut data_view_manager_map = DATA_VIEW_MANAGER_MAP.lock().await;
        let data_view_manager = data_view_manager_map.get_mut(jwt).context("Missing session")?;
        let data_in = req.body_json::<Value>().await?;

        let data_out = match data_view_manager.process(data_in).await {
            Ok(data_out) => data_out,
            Err(err) => {
                let mut response = tide::Response::from(err.to_string());
                response.set_status(500);
                return Ok(response);
            }
        };

        let data_out = serde_json::to_value(data_out)?;
        Ok(data_out.into())
    }
        
    app.at("/wasm_ws/process").post(wasm_process);
    Ok(app)
}

#[cfg(not(target_arch = "wasm32"))]
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

#[cfg(not(target_arch = "wasm32"))]
const DEFAULT_GROUP_OWNER_ADMIN_STR: &str = r#"{"name": "admin"}"#;

#[cfg(not(target_arch = "wasm32"))]
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
