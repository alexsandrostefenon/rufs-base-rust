use std::{collections::HashMap, fs, path::Path, sync::{RwLock, Arc}};

use async_std::path::PathBuf;
use jsonwebtoken::{encode, EncodingKey, Header};
use openapiv3::{OpenAPI, SecurityRequirement};
use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::json;
use tide::{Error, StatusCode};
use tide_websockets::WebSocketConnection;

use crate::{
    db_adapter_file::DbAdapterFile,
    db_adapter_postgres::DbAdapterPostgres,
    entity_manager::EntityManager,
    micro_service_server::{IMicroServiceServer, MicroServiceServer},
    openapi::{FillOpenAPIOptions, RufsOpenAPI},
};

#[derive(Deserialize, Serialize, Default)]
struct RufsGroupOwner {
    id: u64,
    name: String,
}

#[derive(Deserialize, Serialize, Default)]
struct Route {
    path: String,
    controller: String,
    #[serde(rename = "templateUrl")]
    #[serde(default)]
    template_url: String,
}

#[derive(Deserialize, Serialize, Default)]
struct MenuItem {
    menu: String,
    label: String,
    path: String,
}

#[derive(Debug, Serialize, Deserialize, Default)]
pub struct Role {
    pub path: String,
    pub mask: u64,
}

#[derive(Deserialize, Serialize, Default)]
struct RufsUserPublic {
    routes: Box<[Route]>,
    menu: HashMap<String, MenuItem>,
    path: String,
}

#[derive(Deserialize, Serialize, Default)]
#[serde(default)]
struct RufsUser {
    //user_proteced: RufsUserProteced,
    id: u64,
    name: String,
    group_owner: u64,
    //groups:         Box<[u64]>,
    roles: Box<[Role]>,
    //user_public: RufsUserPublic,
    routes: Box<[Route]>,
    menu: HashMap<String, MenuItem>,
    path: String,
    //other
    full_name: String,
    password: String,
}

#[derive(Serialize)]
pub struct LoginResponse<'a> {
    //token_payload : TokenPayload,
    //user_proteced: RufsUserProteced,
    id: u64,
    name: String,
    #[serde(rename = "groupOwner")]
    group_owner: u64,
    groups: Box<[u64]>,
    roles: Box<[Role]>,
    ip: String,
    //user_public: RufsUserPublic,
    routes: Box<[Route]>,
    menu: HashMap<String, MenuItem>,
    path: String,
    #[serde(rename = "jwtHeader")]
    jwt_header: String,
    title: String,
    openapi: &'a OpenAPI,
}

#[derive(Debug, Serialize, Deserialize, Default)]
pub struct Claims {
    sub: String,
    exp: usize,
    id: u64,
    pub name: String,
    #[serde(rename = "groupOwner")]
    pub group_owner: u64,
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
#[derive(Default, Clone)]
pub struct RufsMicroService<'a> {
    pub micro_service_server: MicroServiceServer,
    /*
    dbConfig                  *DbConfig
    */
    pub check_rufs_tables: bool,
    pub migration_path: String,
    pub entity_manager: DbAdapterPostgres<'a>,
    pub db_adapter_file: DbAdapterFile<'a>,
    pub ws_server_connections : Arc<RwLock<HashMap<String, WebSocketConnection>>>,
    pub ws_server_connections_tokens : Arc<RwLock<HashMap<String, Claims>>>,
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
impl RufsMicroService<'_> {
    pub async fn connect(&mut self, db_uri: &str) -> Result<(), Error> {
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
    
        async fn create_rufs_tables(rms: &RufsMicroService<'_>, openapi_rufs: &OpenAPI) -> Result<(), Error> {
            if !rms.check_rufs_tables {
                return Ok(());
            }

            for name in ["rufsGroupOwner", "rufsUser", "rufsGroup", "rufsGroupUser"] {
                if rms.micro_service_server.openapi.components.as_ref().unwrap().schemas.get(name).is_none() {
                    let _schema = openapi_rufs.components.as_ref().unwrap().schemas.get(name).unwrap().as_item().unwrap();
                    //rms.entity_manager.create_table(name, schema)?;
                }
            }

            let _default_group_owner_admin: serde_json::Value = serde_json::from_str(DEFAULT_GROUP_OWNER_ADMIN_STR).unwrap();
            let _default_user_admin: serde_json::Value = serde_json::from_str(DEFAULT_USER_ADMIN_STR).unwrap();

            if rms.entity_manager.find_one(openapi_rufs, "rufsGroupOwner", &json!({"name": "ADMIN"})).await.is_none() {
                //rms.entity_manager.insert("rufsGroupOwner", default_group_owner_admin)?;
            }

            if rms.entity_manager.find_one(openapi_rufs, "rufsUser", &json!({"name": "admin"})).await.is_none() {
                //rms.entity_manager.insert("rufsUser", default_user_admin)?;
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
                let text = fs::read_to_string(PathBuf::from(rms.migration_path.clone()).join(file_name))?;

                for sql in text.split("--split") {
                    if let Err(error) = rms.entity_manager.exec(sql).await {
                        return Err(tide::Error::from_str(500, format!("{}", error)));
                    }
                }

                let new_version = get_version(file_name)?;
                rms.micro_service_server.openapi.info.version = format!("{}.{}.{}", ((new_version / 1000) / 1000) % 1000, (new_version / 1000) % 1000, new_version % 1000);
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

            //rms.entity_manager.UpdateOpenAPI(rms.openapi, FillOpenAPIOptions{requestBodyContentType: rms.requestBodyContentType});
            //rms.StoreOpenAPI("")?
            rms.micro_service_server.store_open_api("")
        }

        self.micro_service_server.connect()?;
        self.entity_manager.connect(db_uri).await.unwrap();
        //self.entity_manager.UpdateOpenAPI(self.openapi, FillOpenAPIOptions{requestBodyContentType: self.requestBodyContentType};

        let openapi_rufs = match serde_json::from_str::<OpenAPI>(RUFS_MICRO_SERVICE_OPENAPI_STR) {
            Ok(openapi) => openapi,
            Err(err) => return Err(tide::Error::from_str(500, format!("{}", err))),
        };
        create_rufs_tables(self, &openapi_rufs).await.unwrap();
        let mut options = FillOpenAPIOptions::default();
        options.security = SecurityRequirement::from([("jwt".to_string(), vec![])]);
        options.schemas = openapi_rufs.components.unwrap().schemas.clone();
        options.request_body_content_type = self.micro_service_server.request_body_content_type.clone();
        self.micro_service_server.openapi.fill(&mut options)?;
        exec_migrations(self).await?;
        //rms.db_adapter_file.openapi = Some(&rms.micro_service_server.openapi);

        if self.check_rufs_tables == false {
            load_file_tables(self)?;
        }

        //RequestFilterUpdateRufsServices(rms.entity_manager, rms.openapi)?;
        Ok(())
    }
}

#[tide::utils::async_trait]
impl IMicroServiceServer for RufsMicroService<'_> {
    async fn authenticate_user(&self, user_name: String, user_password: String, remote_addr: String) -> Result<LoginResponse, Error> {
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
            return Err(Error::from_str(StatusCode::InternalServerError, "Don't match user and password."));
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
            group_owner: user.group_owner,
            groups,
            roles: user.roles,
            ip: remote_addr,
        };
        let secret = std::env::var("RUFS_JWT_SECRET").unwrap_or("123456".to_string());
        let jwt_header = encode(&Header::default(), &claims, &EncodingKey::from_secret(secret.as_ref()))?;
        let login_response = LoginResponse {
            id: user.id,
            name: claims.name.clone(),
            group_owner: user.group_owner,
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
					"name": {"nullable": false, "unique": true}
				},
				"x-primaryKeys": ["id"]
			},
			"rufsUser": {
				"properties": {
					"id":             {"type": "integer", "x-identityGeneration": "BY DEFAULT"},
					"rufsGroupOwner": {"type": "integer", "nullable": false, "$ref": "#/components/schemas/rufsGroupOwner"},
					"name":           {"maxLength": 32, "nullable": false, "unique": true},
					"password":       {"nullable": false},
					"path":           {},
					"roles":          {"type": "array", "items": {"properties": {"name": {"type": "string"}, "mask": {"type": "integer"}}}},
					"routes":         {"type": "array", "items": {"properties": {"path": {"type": "string"}, "controller": {"type": "string"}, "templateUrl": {"type": "string"}}}},
					"menu":           {"type": "object", "properties": {"menu": {"type": "string"}, "label": {"type": "string"}, "path": {"type": "string"}}}
				},
				"x-primaryKeys": ["id"],
				"x-uniqueKeys":  {}
			},
			"rufsGroup": {
				"properties": {
					"id":   {"type": "integer", "x-identityGeneration": "BY DEFAULT"},
					"name": {"nullable": false, "unique": true}
				},
				"x-primaryKeys": ["id"]
			},
			"rufsGroupUser": {
				"properties": {
					"rufsUser":  {"type": "integer", "nullable": false, "$ref": "#/components/schemas/rufsUser"},
					"rufsGroup": {"type": "integer", "nullable": false, "$ref": "#/components/schemas/rufsGroup"}
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
		"menu": {},
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
				"controller": "OpenAPIOperationObjectController",
				"path": "/app/rufs_service/:action"
			},
			{
				"controller": "UserController",
				"path": "/app/rufs_user/:action"
			}
		]
	}"#;
