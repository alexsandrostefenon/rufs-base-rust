use std::fs;

use tide::Error;

use crate::rufs_micro_service::LoginResponse;

use openapiv3::OpenAPI;

#[derive(serde::Deserialize, Default)]
pub struct LoginRequest {
    pub user: String,
    pub password: String,
}

#[tide::utils::async_trait]
pub trait IMicroServiceServer {
    async fn authenticate_user(&self, user_name: String, user_password: String, remote_addr: String) -> Result<LoginResponse, Error>;
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
    pub openapi_file_name : String,
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
            openapi_file_name: "".to_string()
        }
    }
}

impl MicroServiceServer {
    fn load_open_api(&mut self) -> Result<(), Error> {
        if self.openapi_file_name.is_empty() {
            self.openapi_file_name = format!("openapi-{}.json", self.app_name);
        }

        let file = fs::File::open(&self.openapi_file_name)?;
        self.openapi = serde_json::from_reader(file)?;
        Ok(())
    }
    
    pub fn store_open_api(&self, file_name :&str) -> Result<(), Error> {
        let file_name = if file_name.is_empty() {
            format!("openapi-{}-rust.json", self.app_name)
        } else {
            file_name.to_string()
        };

        let contents = serde_json::to_string_pretty(&self.openapi)?;
        std::fs::write(file_name, contents)?;
        Ok(())
    }
    
    pub fn connect(&mut self) -> Result<(), Error> {
        self.load_open_api()?;
        Ok(())
    }
}

#[tide::utils::async_trait]
impl IMicroServiceServer for MicroServiceServer {
    async fn authenticate_user(&self, user_name: String, user_password: String, remote_addr: String) -> Result<LoginResponse, Error> {
        println!("[MicroServiceServer.authenticate_user({}, {}, {})]", user_name, user_password, remote_addr);
        todo!()
    }
}
