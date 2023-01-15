use std::{pin::Pin, future::Future};

use micro_service_server::LoginRequest;
use request_filter::RequestFilter;
use serde_json::Value;
use tide::{Request, Response, Result, Next, StatusCode, Body};

use crate::{micro_service_server::IMicroServiceServer, rufs_micro_service::{RufsMicroService}};

pub mod data_store;
pub mod db_adapter_file;
pub mod db_adapter_postgres;
pub mod entity_manager;
pub mod micro_service_server;
pub mod openapi;
pub mod request_filter;
pub mod rufs_micro_service;
/*
#[derive(Default)]
struct TideRufsMicroService;

#[tide::utils::async_trait]
impl<State: Clone + Send + Sync + 'static> Middleware<State> for TideRufsMicroService {
    async fn handle(&self, mut request: Request<State>, next: Next<'_, State>) -> tide::Result {
    }
}
*/
fn handle<'a>(
    request: Request<RufsMicroService>,
    next: Next<'a, RufsMicroService>,
) -> Pin<Box<dyn Future<Output = Result> + Send + 'a>> {
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

        let path = request.url().path()[1..].to_string();
        let rufs = request.state();

        if path.starts_with(&rufs.micro_service_server.api_path) == false {
            let name = if path.ends_with("/") || path.is_empty() {
                path.clone() + &"index.html".to_string()
            } else {
                path.clone()
            };

            let current_dir = std::env::current_dir().unwrap();

            for folder in &rufs.micro_service_server.serve_static_paths {
                let file = current_dir.join(folder).join(&name);

                if file.exists() {
                    match tide::Body::from_file(&file).await {
                        Ok(body) => return Ok(Response::builder(StatusCode::Ok).body(body).build()),
                        Err(e) => return Err(e.into()),
                    }
                } else {
                    //println!("[MicroServiceServer.listen().serve_dir()] current_dir = {}, folder = {}, name = {} don't found.", current_dir.to_str().unwrap(), folder.to_str().unwrap(), path);
                }
            }
        }

        return Ok(next.run(request).await);
    })
}

async fn handle_login(mut request: Request<RufsMicroService>) -> tide::Result {
    let login_request = request.body_json::<LoginRequest>().await?;
    let rufs = request.state();

    if login_request.user.is_empty() || login_request.password.is_empty() {
        println!("Login request is empty");
    }

    let login_response = match rufs.authenticate_user(login_request.user.clone(), login_request.password.clone(), request.remote().unwrap().to_string().clone()) {
        Ok(login_response) => login_response,
        Err(error) => {
            println!("[RufsMicroService.handle.login.authenticate_user] : {}", error);
            return Err(error.into());
        }
    };

    Ok(Response::builder(StatusCode::Ok).body(Body::from_json(&login_response)?).build())
}

async fn handle_api(mut request: Request<RufsMicroService>) -> tide::Result {
    let obj_in = request.body_json::<Value>().await?;
    let rufs = request.state();
    let mut rf = RequestFilter::new(&request, rufs, obj_in).await.unwrap();

    let response = match rf.check_authorization(&request) {
        Ok(true) => rf.process_request(),
        Ok(false) => Response::builder(StatusCode::Unauthorized).build(),
        Err(err) => tide::Response::builder(StatusCode::BadRequest)
            .body(format!("[RufsMicroService.OnRequest.CheckAuthorization] : {}", err))
            .build(),
    };

    Ok(response)
}

#[async_std::main]
async fn main() -> tide::Result<()> {
    let mut rufs = RufsMicroService::default();
    rufs.micro_service_server.serve_static_paths = vec![
        std::path::Path::new("rufs-nfe-es6/webapp").to_path_buf(),
        std::path::Path::new("rufs-crud-es6/webapp").to_path_buf(),
        std::path::Path::new("rufs-base-es6/webapp").to_path_buf(),
    ];
    rufs.init()?;
    let api_path = rufs.micro_service_server.api_path.clone();
    let listen = format!("127.0.0.1:{}", rufs.micro_service_server.port);
    let mut app = tide::with_state(rufs);

    app.at(&format!("/{}/login", &api_path)).post(handle_login);
    app.at(&api_path).all(handle_api);

    app.at("/websocket").with(tide_websockets::WebSocket::new(|request, mut stream| async move {
        while let Some(Ok(tide_websockets::Message::Text(input))) = async_std::stream::StreamExt::next(&mut stream).await {
            let token: String = input.chars().rev().collect();
            let x = stream.clone();
            let rufs :&RufsMicroService= request.state();
            rufs.ws_server_connections.write().unwrap().insert(token, x);
        }

        Ok(())
    }));

    app.with(handle);

    app.listen(listen).await?;
    Ok(())
}
