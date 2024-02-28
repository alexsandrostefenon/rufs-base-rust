pub mod data_store;
#[cfg(not(target_arch = "wasm32"))]
#[cfg(feature = "db_file_json")]
pub mod db_adapter_file;
#[cfg(not(target_arch = "wasm32"))]
#[cfg(feature = "postgres")]
pub mod db_adapter_postgres;
#[cfg(not(target_arch = "wasm32"))]
#[cfg(any(feature = "db_file_json", feature = "postgres"))]
pub mod entity_manager;
#[cfg(not(target_arch = "wasm32"))]
pub mod micro_service_server;
pub mod openapi;
#[cfg(not(target_arch = "wasm32"))]
#[cfg(feature = "http_server")]
pub mod request_filter;
#[cfg(feature = "http_server")]
pub mod rufs_micro_service;

#[cfg(not(target_arch = "wasm32"))]
#[cfg(feature = "tide")]
pub async fn rufs_tide_new(rufs: rufs_micro_service::RufsMicroService<'static>) -> Result<Box<tide::Server<rufs_micro_service::RufsMicroService<'static>>>, Box<dyn std::error::Error>> {
    use jsonwebtoken::{decode, DecodingKey, Validation};
    use serde_json::Value;
    use std::{future::Future, pin::Pin};
    use async_std::path::Path;
    use tide::{Response, Next, StatusCode, Body, http::{mime}};
    use micro_service_server::{LoginRequest};
    use request_filter::RequestFilter;
    use crate::{micro_service_server::IMicroServiceServer, rufs_micro_service::{RufsMicroService, Claims}};

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
    Ok(app)
}
