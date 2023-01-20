use tide::Error;

use crate::rufs_micro_service::LoginResponse;

use openapiv3::OpenAPI;

#[derive(serde::Deserialize, Default)]
pub struct LoginRequest {
    pub user: String,
    pub password: String,
}

pub trait IMicroServiceServer {
    fn init(&mut self, db_uri: &str) -> Result<(), Error>;
    fn authenticate_user(&self, user_name: String, user_password: String, remote_addr: String) -> Result<LoginResponse, Error>;
}

#[derive(Clone)]
pub struct MicroServiceServer {
    pub app_name: String,
    //protocol : String,
    pub port: u16,
    //addr : String,
    pub api_path: String,
    //security : String,
    pub request_body_content_type: String,
    //openapi_file_name : String,
    pub openapi: OpenAPI,
    //wsServerConnections    : HashMap<String, websocketConn>,
}

impl Default for MicroServiceServer {
    fn default() -> Self {
        Self {
            port: 8080,
            api_path: "rest".to_string(),
            openapi: Default::default(),
            app_name: "base".to_string(),
            request_body_content_type: "application/json".to_string(),
        }
    }
}

impl IMicroServiceServer for MicroServiceServer {
    fn init(&mut self, _db_uri: &str) -> Result<(), Error> {
        Ok(())
    }

    fn authenticate_user(&self, user_name: String, user_password: String, remote_addr: String) -> Result<LoginResponse, Error> {
        println!("[MicroServiceServer.authenticate_user({}, {}, {})]", user_name, user_password, remote_addr);
        todo!()
    }
}
