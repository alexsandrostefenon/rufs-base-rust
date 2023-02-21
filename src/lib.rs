use jsonwebtoken::{decode, DecodingKey, Validation};
use micro_service_server::{LoginRequest};
use request_filter::RequestFilter;
use serde_json::Value;
use tide::{Request, Response, Next, StatusCode, Body, Middleware, Error, Server, http::{mime}};

use crate::{micro_service_server::IMicroServiceServer, rufs_micro_service::{RufsMicroService, Claims}};

pub mod data_store;
pub mod db_adapter_file;
pub mod db_adapter_postgres;
pub mod entity_manager;
pub mod micro_service_server;
pub mod openapi;
pub mod request_filter;
pub mod rufs_micro_service;

#[derive(Default)]
struct TideRufsMicroService {
    serve_static_paths: Vec<std::path::PathBuf>
}

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

async fn handle_login(mut request: Request<RufsMicroService<'_>>) -> tide::Result {
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

async fn handle_api(mut request: Request<RufsMicroService<'_>>) -> tide::Result {
    let method = request.method().to_string().to_lowercase();
    let auth = request.header("Authorization").unwrap().as_str();
    print!("\n\ncurl -X '{}' {} -H 'Authorization: {}'", method, request.url(), auth);

    let obj_in = if method == "post" || method == "put" || method == "patch" {
        let obj_in = request.body_json::<Value>().await?;
        println!(" -d '{}'", obj_in);
        obj_in
    } else {
        println!();
        Value::Null
    };

    let rufs = request.state();
    let mut rf = RequestFilter::new(&request, rufs, &method, obj_in).unwrap();

    let response = match rf.check_authorization(&request).await {
        Ok(true) => rf.process_request().await,
        Ok(false) => Response::builder(StatusCode::Unauthorized).build(),
        Err(err) => tide::Response::builder(StatusCode::BadRequest)
            .body(format!("[RufsMicroService.OnRequest.CheckAuthorization] : {}", err))
            .build(),
    };

    Ok(response)
}

pub async fn rufs_tide_new(options: &RufsMicroService<'static>, base_dir: &str) -> Result<Box<Server<RufsMicroService<'static>>>, Error> {
    let mut rufs = RufsMicroService{..options.clone()};
    rufs.connect(&format!("postgres://development:123456@localhost:5432/{}", rufs.micro_service_server.app_name)).await?;
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
        std::path::Path::new(base_dir).join("rufs-nfe-es6/webapp").to_path_buf(),
        std::path::Path::new(base_dir).join("rufs-crud-es6/webapp").to_path_buf(),
        std::path::Path::new(base_dir).join("rufs-base-es6/webapp").to_path_buf(),
    ];
    app.with(TideRufsMicroService{serve_static_paths});
    Ok(app)
}

#[cfg(test)]
mod tests {
    use crate::{rufs_tide_new, rufs_micro_service::RufsMicroService, micro_service_server::MicroServiceServer};

    async fn nfe(base_dir: &str) -> tide::Result<()> {
        let options = RufsMicroService{
            check_rufs_tables: true,
            migration_path: format!("{}rufs-nfe-es6/sql", base_dir),
            micro_service_server: MicroServiceServer{app_name: "rufs_nfe".to_string(), ..Default::default()}, 
            ..Default::default()
        };
    
        let app = rufs_tide_new(&options, base_dir).await?;
        let rufs = app.state();
        let listen = format!("127.0.0.1:{}", rufs.micro_service_server.port);
        println!("listening of {}", listen);
        app.listen(listen).await.unwrap();
    
        //sleep(Duration::from_millis(60000)).await;
        // TODO : run selenium ide scripts
        /*
        let url = Url::parse(&listen).unwrap();
        let req = Request::new(Method::Get, url);
        let mut res: Response = app.respond(req).await?;
        assert_eq!("Hello, world", res.body_string().await?);        
        */
        Ok(())
    }

    #[tokio::test]
    async fn nfe_local() -> tide::Result<()> {
        nfe("../").await
    }

    #[tokio::test]
    async fn nfe_workspace() -> tide::Result<()> {
        nfe("./").await
    }

}
