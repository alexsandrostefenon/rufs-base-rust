#[cfg(feature = "http_server")]
use jsonwebtoken::{decode, DecodingKey, Validation};
#[cfg(feature = "http_server")]
use micro_service_server::{LoginRequest};
#[cfg(feature = "http_server")]
use request_filter::RequestFilter;
#[cfg(feature = "http_server")]
use serde_json::Value;

#[cfg(feature = "tide")]
use tide::{Request, Response, Next, StatusCode, Body, Middleware, Error, Server, http::{mime}};

#[cfg(feature = "http_server")]
use crate::{micro_service_server::IMicroServiceServer, rufs_micro_service::{RufsMicroService, Claims}};

pub mod data_store;
#[cfg(feature = "db_file_json")]
pub mod db_adapter_file;
#[cfg(feature = "postgres")]
pub mod db_adapter_postgres;
#[cfg(any(feature = "db_file_json", feature = "postgres"))]
pub mod entity_manager;
pub mod micro_service_server;
pub mod openapi;
#[cfg(feature = "http_server")]
pub mod request_filter;
pub mod rufs_micro_service;

#[cfg(feature = "tide")]
#[derive(Default)]
struct TideRufsMicroService {
    serve_static_paths: Vec<std::path::PathBuf>
}

#[cfg(feature = "tide")]
#[tide::utils::async_trait]
impl<State: Clone + Send + Sync + 'static> Middleware<State> for TideRufsMicroService {

    async fn handle(&self, request: Request<State>, next: Next<'_, State>) -> tide::Result {
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

        let path = request.url().path()[1..].to_string();

        let name = if path.ends_with("/") || path.is_empty() {
            path.clone() + &"index.html".to_string()
        } else {
            path.clone()
        };

        let current_dir = std::env::current_dir().unwrap();

        for folder in &self.serve_static_paths {
            let file = current_dir.join(folder).join(&name);

            if file.exists() {
                match tide::Body::from_file(&file).await {
                    Ok(body) => return Ok(Response::builder(StatusCode::Ok).body(body).build()),
                    Err(e) => return Err(e.into()),
                }
            }
        }

        return Ok(next.run(request).await);
    }

}

#[cfg(feature = "tide")]
async fn handle_login(mut request: Request<RufsMicroService<'_>>) -> tide::Result {
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

#[cfg(feature = "tide")]
async fn handle_api(mut request: Request<RufsMicroService<'_>>) -> tide::Result {
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

#[cfg(feature = "tide")]
pub async fn rufs_tide_new(rufs: RufsMicroService<'static>, base_dir: &str) -> Result<Box<Server<RufsMicroService<'static>>>, Error> {
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

    app.at(&format!("/{}/login", &api_path)).post(handle_login);
    app.at(&format!("/{}/*", &api_path)).all(handle_api);
    let serve_static_paths = vec![
        //std::path::Path::new(base_dir).join("rufs-nfe-es6/webapp").to_path_buf(),
        std::path::Path::new(base_dir).join("rufs-crud-rust/pkg").to_path_buf(),
        std::path::Path::new(base_dir).join("rufs-crud-rust/webapp").to_path_buf(),
    ];
    app.with(TideRufsMicroService{serve_static_paths});
    Ok(app)
}

#[cfg(feature = "tide")]
#[cfg(test)]
mod tests {
    use serde_json::Value;
    use crate::openapi::*;
    
    use crate::{rufs_tide_new, rufs_micro_service::RufsMicroService, micro_service_server::MicroServiceServer};

    #[tokio::test]
    async fn nfe() -> Result<(),Box<dyn std::error::Error>> {
      let base_dir = if std::env::current_dir()?.to_string_lossy().ends_with("/rufs-base-rust") {
        "../"
      } else {
        "./"
      };

      let mut rufs = RufsMicroService{
        check_rufs_tables: true,
        migration_path: format!("{}rufs-nfe-es6/sql", base_dir),
        micro_service_server: MicroServiceServer{
          //openapi_file_name: format!("{}rufs-base-rust/openapi-rufs_nfe-rust.json", base_dir),
          app_name: "rufs_nfe".to_string(), ..Default::default()
        }, 
        ..Default::default()
      };

      rufs.connect(&format!("postgres://development:123456@localhost:5432/{}", rufs.micro_service_server.app_name)).await?;

      if let Some(field) = rufs.micro_service_server.openapi.get_property_mut("requestProduct", "request") {
        field.schema_data.extensions.insert("x-title".to_string(), Value::String("Lista de produtos/componentes".to_string()));
      }

      if let Some(field) = rufs.micro_service_server.openapi.get_property_mut("requestPayment", "request") {
        field.schema_data.extensions.insert("x-title".to_string(), Value::String("Lista de pagamentos".to_string()));
      }

      if let Some(field) = rufs.micro_service_server.openapi.get_property_mut("person", "cnpjCpf") {
        field.schema_data.extensions.insert("x-shortDescription".to_string(), Value::Bool(true));
      }

      if let Some(field) = rufs.micro_service_server.openapi.get_property_mut("person", "name") {
        field.schema_data.extensions.insert("x-shortDescription".to_string(), Value::Bool(true));
      }

      if let Some(field) = rufs.micro_service_server.openapi.get_property_mut("account", "person") {
        field.schema_data.extensions.insert("x-shortDescription".to_string(), Value::Bool(true));
      }

      if let Some(field) = rufs.micro_service_server.openapi.get_property_mut("account", "description") {
        field.schema_data.extensions.insert("x-shortDescription".to_string(), Value::Bool(true));
      }

      rufs.micro_service_server.store_open_api("")?;
      let app = rufs_tide_new(rufs, base_dir).await?;
      let rufs = app.state();
      let listen = format!("127.0.0.1:{}", rufs.micro_service_server.port);
      println!("listening of {}", listen);
      app.listen(listen).await.unwrap();
      Ok(())
    }

}
