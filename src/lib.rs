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
        std::path::Path::new(base_dir).join("rufs-crud-rust/pkg").to_path_buf(),
        std::path::Path::new(base_dir).join("rufs-crud-rust/webapp").to_path_buf(),
    ];
    app.with(TideRufsMicroService{serve_static_paths});
    Ok(app)
}

#[cfg(feature = "tide")]
#[cfg(test)]
mod tests {
    use openapiv3::*;
    use serde_json::{Value, json};
    use crate::openapi::*;
    
    use crate::{rufs_tide_new, rufs_micro_service::RufsMicroService, micro_service_server::MicroServiceServer};

    #[tokio::test]
    async fn nfe() -> tide::Result<()> {
      let base_dir = if std::env::current_dir()?.ends_with("/rufs-base-rust") {
        "../"
      } else {
        "./"
      };

      let options = RufsMicroService{
          check_rufs_tables: true,
          migration_path: format!("{}rufs-nfe-es6/sql", base_dir),
          micro_service_server: MicroServiceServer{
            openapi_file_name: format!("{}rufs-base-rust/openapi-rufs_nfe-rust.json", base_dir),
            app_name: "rufs_nfe".to_string(), ..Default::default()
          }, 
          ..Default::default()
      };
  
      let app = rufs_tide_new(&options, base_dir).await?;
      let mut rufs = app.state();

      if let Some(field) = rufs.micro_service_server.openapi.get_property("requestProduct", "request") {
        if let Some(extension) = field.schema_data.extensions.get("x-title") {

        }
      }

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
/*
    #[test]
    fn rufs_openapi() {
        let openapi = serde_json::from_str::<OpenAPI>(OPENAPI_TEST).unwrap();

        {
            let res = openapi.copy_fields("/rufs_user", "get", &SchemaPlace::Response, false, &json!({"id":2,"rufsGroupOwner":2,"name":"guest","password":"e10adc3949ba59abbe56e057f20f883e","path":"request/search","roles":[{"mask":1,"path":"/rufs_group_owner","$$hashKey":"object:403"},{"mask":1,"path":"/rufs_group","$$hashKey":"object:404"},{"mask":1,"path":"/nfe_cfop","$$hashKey":"object:405"},{"mask":1,"path":"/bacen_country","$$hashKey":"object:406"},{"mask":1,"path":"/ibge_uf","$$hashKey":"object:407"},{"mask":1,"path":"/ibge_city","$$hashKey":"object:408"},{"mask":1,"path":"/ibge_cnae","$$hashKey":"object:409"},{"mask":1,"path":"/camex_ncm","$$hashKey":"object:410"},{"mask":1,"path":"/confaz_cest","$$hashKey":"object:411"},{"mask":1,"path":"/nfe_tax_group","$$hashKey":"object:412"},{"mask":23,"path":"/person","$$hashKey":"object:413"},{"mask":23,"path":"/account","$$hashKey":"object:414"},{"mask":1,"path":"/stock_action","$$hashKey":"object:415"},{"mask":1,"path":"/request_type","$$hashKey":"object:416"},{"mask":1,"path":"/request_state","$$hashKey":"object:417"},{"mask":1,"path":"/payment_type","$$hashKey":"object:418"},{"mask":1,"path":"/nfe_st_icms_origem","$$hashKey":"object:419"},{"mask":23,"path":"/product","$$hashKey":"object:420"},{"mask":7,"path":"/service","$$hashKey":"object:421"},{"mask":7,"path":"/barcode","$$hashKey":"object:422"},{"path":"/request","mask":31},{"mask":23,"path":"/request_product","$$hashKey":"object:424"},{"mask":23,"path":"/request_service","$$hashKey":"object:425"},{"mask":23,"path":"/request_payment","$$hashKey":"object:426"},{"mask":23,"path":"/request_nfe","$$hashKey":"object:427"},{"mask":23,"path":"/request_freight","$$hashKey":"object:428"},{"mask":7,"path":"/stock","$$hashKey":"object:429"}],"routes":[{"controller":"RequestController","path":"/app/request/:action","$$hashKey":"object:652"}],"menu":[{"group":"actions","label":"Importar","path":"request/import?overwrite.type=1&overwrite.state=10","$$hashKey":"object:572"},{"group":"actions","label":"Compra","path":"request/new?overwrite.type=1&overwrite.state=10","$$hashKey":"object:573"},{"group":"actions","label":"Venda","path":"request/new?overwrite.type=2&overwrite.state=10","$$hashKey":"object:574"},{"group":"form","label":"Financeiro","path":"request_payment/search","$$hashKey":"object:575"},{"group":"form","label":"Estoque","path":"stock/search","$$hashKey":"object:576"},{"group":"form","label":"Produtos","path":"product/search","$$hashKey":"object:577"},{"group":"form","label":"Clientes e Fornecedores","path":"person/search","$$hashKey":"object:578"},{"group":"form","label":"Requisições","path":"request/search","$$hashKey":"object:579"},{"group":"form","label":"Contas","path":"account/search","$$hashKey":"object:580"}]}), false, false, false);
            println!("{:?}", res);
        }

        {
            let res = openapi.get_schema_from_responses("rufsUserList", false);
            println!("{:?}", res);
        }

        {
            let res = openapi.copy_value("/rufs_user", "get", &SchemaPlace::Response, false, "menu", &Value::String("action".to_string()));
            println!("{:?}", res);
        }

        {
            let schema = openapi.get_schema("/rufs_user", "get", &SchemaPlace::Response, false).unwrap();
            let str = serde_json::to_string(schema).unwrap();
            print!("[rufs_openapi(get_schema)] : {}", str);
        }

        {
            let res = openapi.copy_value("/request_payment", "put", &SchemaPlace::Response, false, "dueDate", &Value::String("2018-05-18T23:08:34.000Z".to_string()));
            println!("{:?}", res);
        }

        {
            let res = openapi.get_foreign_key("requestProduct", "request", &json!({"rufsGroupOwner":2,"id":1}));
            println!("{:?}", res);
        }

        {
            let res = openapi.get_foreign_key("requestProduct", "request", &json!({"rufsGroupOwner":2,"id":1}));
            println!("{:?}", res);
        }

        {
            let res = openapi.copy_fields("/request", "get", &SchemaPlace::Response, false, &json!({"type":1,"state":10,"person":"93209765016110","personDest":"80803792034","date":"2018-05-18T23:08:34.000Z","productsValue":0,"servicesValue":0,"transportValue":0,"descValue":0,"sumValue":0,"paymentsValue":0}), false, false, false);
            println!("{:?}", res);
        }

        {
            let res = openapi.get_foreign_key("person", "country", &json!({"abr":"BR","id":1058,"name":"Brazil","namePt":"Brasil"}));
            println!("{:?}", res);
        }

        {
            let res = openapi.get_primary_key_foreign("/ibge_uf", "country", &json!({"id":53,"country":1058,"name":"Distrito Federal","abr":"DF","ddd":"61"}));
            println!("{:?}", res);
        }

        {
            let res = openapi.get_foreign_key_description("ibgeUf", "country");
            println!("{:?}", res);
        }

        {
            let res = openapi.get_primary_key_foreign("ibgeUf", "country", &json!({"abr":"DF","country":1058,"ddd":"61","id":53,"name":"Distrito Federal"}));
            println!("{:?}", res);
        }

        {
            openapi.copy_fields("/rufs_group_owner", "get", &SchemaPlace::Parameter, true, &Value::Null, false, false, false).unwrap();            
        }

        {
            let schema = openapi.get_schema("/request", "post", &SchemaPlace::Request, false).unwrap();
            let str = serde_json::to_string(schema).unwrap();
            print!("[rufs_openapi(get_schema)] : {}", str);
        }

        {
            let schema = openapi.get_schema("/rufs_group_owner", "get", &SchemaPlace::Response, false).unwrap();
            let str = serde_json::to_string(schema).unwrap();
            print!("[rufs_openapi(get_schema)] : {}", str);
        }

        {
            let mut list = vec![];
            openapi.get_dependencies("rufsGroupOwner", &mut list);
            print!("[rufs_openapi(get_dependencies)] : {:?}", list);
        }
    }
*/
    const OPENAPI_TEST: &str = r##"{
        "openapi": "3.0.3",
        "info": {
          "title": "rufs-base-es6 openapi genetator",
          "description": "CRUD operations",
          "version": "1.0.2"
        },
        "paths": {
          "/login": {
            "post": {
              "tags": [
                "login"
              ],
              "description": "CRUD post operation over login",
              "operationId": "login",
              "requestBody": {
                "$ref": "#/components/requestBodies/login"
              },
              "responses": {
                "default": {
                  "$ref": "#/components/responses/Error"
                },
                "200": {
                  "$ref": "#/components/responses/login"
                }
              }
            }
          },
          "/account": {
            "get": {
              "tags": [
                "account"
              ],
              "description": "CRUD get operation over account",
              "operationId": "zzz_get_account",
              "parameters": [
                {
                  "$ref": "#/components/parameters/account"
                }
              ],
              "responses": {
                "default": {
                  "$ref": "#/components/responses/Error"
                },
                "200": {
                  "$ref": "#/components/responses/accountList"
                }
              }
            },
            "put": {
              "tags": [
                "account"
              ],
              "description": "CRUD put operation over account",
              "operationId": "zzz_put_account",
              "parameters": [
                {
                  "$ref": "#/components/parameters/account"
                }
              ],
              "requestBody": {
                "$ref": "#/components/requestBodies/account"
              },
              "responses": {
                "default": {
                  "$ref": "#/components/responses/Error"
                },
                "200": {
                  "$ref": "#/components/responses/account"
                }
              }
            },
            "post": {
              "tags": [
                "account"
              ],
              "description": "CRUD post operation over account",
              "operationId": "zzz_post_account",
              "requestBody": {
                "$ref": "#/components/requestBodies/account"
              },
              "responses": {
                "default": {
                  "$ref": "#/components/responses/Error"
                },
                "200": {
                  "$ref": "#/components/responses/account"
                }
              }
            },
            "delete": {
              "tags": [
                "account"
              ],
              "description": "CRUD delete operation over account",
              "operationId": "zzz_delete_account",
              "parameters": [
                {
                  "$ref": "#/components/parameters/account"
                }
              ],
              "responses": {
                "default": {
                  "$ref": "#/components/responses/Error"
                },
                "200": {
                  "$ref": "#/components/responses/account"
                }
              }
            },
            "patch": {
              "tags": [
                "account"
              ],
              "description": "CRUD patch operation over account",
              "operationId": "zzz_patch_account",
              "parameters": [
                {
                  "$ref": "#/components/parameters/account"
                }
              ],
              "requestBody": {
                "$ref": "#/components/requestBodies/account"
              },
              "responses": {
                "default": {
                  "$ref": "#/components/responses/Error"
                },
                "200": {
                  "$ref": "#/components/responses/account"
                }
              }
            }
          },
          "/bacen_country": {
            "get": {
              "tags": [
                "bacenCountry"
              ],
              "description": "CRUD get operation over bacenCountry",
              "operationId": "zzz_get_bacenCountry",
              "parameters": [
                {
                  "$ref": "#/components/parameters/bacenCountry"
                }
              ],
              "responses": {
                "default": {
                  "$ref": "#/components/responses/Error"
                },
                "200": {
                  "$ref": "#/components/responses/bacenCountryList"
                }
              }
            },
            "put": {
              "tags": [
                "bacenCountry"
              ],
              "description": "CRUD put operation over bacenCountry",
              "operationId": "zzz_put_bacenCountry",
              "parameters": [
                {
                  "$ref": "#/components/parameters/bacenCountry"
                }
              ],
              "requestBody": {
                "$ref": "#/components/requestBodies/bacenCountry"
              },
              "responses": {
                "default": {
                  "$ref": "#/components/responses/Error"
                },
                "200": {
                  "$ref": "#/components/responses/bacenCountry"
                }
              }
            },
            "post": {
              "tags": [
                "bacenCountry"
              ],
              "description": "CRUD post operation over bacenCountry",
              "operationId": "zzz_post_bacenCountry",
              "requestBody": {
                "$ref": "#/components/requestBodies/bacenCountry"
              },
              "responses": {
                "default": {
                  "$ref": "#/components/responses/Error"
                },
                "200": {
                  "$ref": "#/components/responses/bacenCountry"
                }
              }
            },
            "delete": {
              "tags": [
                "bacenCountry"
              ],
              "description": "CRUD delete operation over bacenCountry",
              "operationId": "zzz_delete_bacenCountry",
              "parameters": [
                {
                  "$ref": "#/components/parameters/bacenCountry"
                }
              ],
              "responses": {
                "default": {
                  "$ref": "#/components/responses/Error"
                },
                "200": {
                  "$ref": "#/components/responses/bacenCountry"
                }
              }
            },
            "patch": {
              "tags": [
                "bacenCountry"
              ],
              "description": "CRUD patch operation over bacenCountry",
              "operationId": "zzz_patch_bacenCountry",
              "parameters": [
                {
                  "$ref": "#/components/parameters/bacenCountry"
                }
              ],
              "requestBody": {
                "$ref": "#/components/requestBodies/bacenCountry"
              },
              "responses": {
                "default": {
                  "$ref": "#/components/responses/Error"
                },
                "200": {
                  "$ref": "#/components/responses/bacenCountry"
                }
              }
            }
          },
          "/barcode": {
            "get": {
              "tags": [
                "barcode"
              ],
              "description": "CRUD get operation over barcode",
              "operationId": "zzz_get_barcode",
              "parameters": [
                {
                  "$ref": "#/components/parameters/barcode"
                }
              ],
              "responses": {
                "default": {
                  "$ref": "#/components/responses/Error"
                },
                "200": {
                  "$ref": "#/components/responses/barcodeList"
                }
              }
            },
            "put": {
              "tags": [
                "barcode"
              ],
              "description": "CRUD put operation over barcode",
              "operationId": "zzz_put_barcode",
              "parameters": [
                {
                  "$ref": "#/components/parameters/barcode"
                }
              ],
              "requestBody": {
                "$ref": "#/components/requestBodies/barcode"
              },
              "responses": {
                "default": {
                  "$ref": "#/components/responses/Error"
                },
                "200": {
                  "$ref": "#/components/responses/barcode"
                }
              }
            },
            "post": {
              "tags": [
                "barcode"
              ],
              "description": "CRUD post operation over barcode",
              "operationId": "zzz_post_barcode",
              "requestBody": {
                "$ref": "#/components/requestBodies/barcode"
              },
              "responses": {
                "default": {
                  "$ref": "#/components/responses/Error"
                },
                "200": {
                  "$ref": "#/components/responses/barcode"
                }
              }
            },
            "delete": {
              "tags": [
                "barcode"
              ],
              "description": "CRUD delete operation over barcode",
              "operationId": "zzz_delete_barcode",
              "parameters": [
                {
                  "$ref": "#/components/parameters/barcode"
                }
              ],
              "responses": {
                "default": {
                  "$ref": "#/components/responses/Error"
                },
                "200": {
                  "$ref": "#/components/responses/barcode"
                }
              }
            },
            "patch": {
              "tags": [
                "barcode"
              ],
              "description": "CRUD patch operation over barcode",
              "operationId": "zzz_patch_barcode",
              "parameters": [
                {
                  "$ref": "#/components/parameters/barcode"
                }
              ],
              "requestBody": {
                "$ref": "#/components/requestBodies/barcode"
              },
              "responses": {
                "default": {
                  "$ref": "#/components/responses/Error"
                },
                "200": {
                  "$ref": "#/components/responses/barcode"
                }
              }
            }
          },
          "/camex_ncm": {
            "get": {
              "tags": [
                "camexNcm"
              ],
              "description": "CRUD get operation over camexNcm",
              "operationId": "zzz_get_camexNcm",
              "parameters": [
                {
                  "$ref": "#/components/parameters/camexNcm"
                }
              ],
              "responses": {
                "default": {
                  "$ref": "#/components/responses/Error"
                },
                "200": {
                  "$ref": "#/components/responses/camexNcmList"
                }
              }
            },
            "put": {
              "tags": [
                "camexNcm"
              ],
              "description": "CRUD put operation over camexNcm",
              "operationId": "zzz_put_camexNcm",
              "parameters": [
                {
                  "$ref": "#/components/parameters/camexNcm"
                }
              ],
              "requestBody": {
                "$ref": "#/components/requestBodies/camexNcm"
              },
              "responses": {
                "default": {
                  "$ref": "#/components/responses/Error"
                },
                "200": {
                  "$ref": "#/components/responses/camexNcm"
                }
              }
            },
            "post": {
              "tags": [
                "camexNcm"
              ],
              "description": "CRUD post operation over camexNcm",
              "operationId": "zzz_post_camexNcm",
              "requestBody": {
                "$ref": "#/components/requestBodies/camexNcm"
              },
              "responses": {
                "default": {
                  "$ref": "#/components/responses/Error"
                },
                "200": {
                  "$ref": "#/components/responses/camexNcm"
                }
              }
            },
            "delete": {
              "tags": [
                "camexNcm"
              ],
              "description": "CRUD delete operation over camexNcm",
              "operationId": "zzz_delete_camexNcm",
              "parameters": [
                {
                  "$ref": "#/components/parameters/camexNcm"
                }
              ],
              "responses": {
                "default": {
                  "$ref": "#/components/responses/Error"
                },
                "200": {
                  "$ref": "#/components/responses/camexNcm"
                }
              }
            },
            "patch": {
              "tags": [
                "camexNcm"
              ],
              "description": "CRUD patch operation over camexNcm",
              "operationId": "zzz_patch_camexNcm",
              "parameters": [
                {
                  "$ref": "#/components/parameters/camexNcm"
                }
              ],
              "requestBody": {
                "$ref": "#/components/requestBodies/camexNcm"
              },
              "responses": {
                "default": {
                  "$ref": "#/components/responses/Error"
                },
                "200": {
                  "$ref": "#/components/responses/camexNcm"
                }
              }
            }
          },
          "/confaz_cest": {
            "get": {
              "tags": [
                "confazCest"
              ],
              "description": "CRUD get operation over confazCest",
              "operationId": "zzz_get_confazCest",
              "parameters": [
                {
                  "$ref": "#/components/parameters/confazCest"
                }
              ],
              "responses": {
                "default": {
                  "$ref": "#/components/responses/Error"
                },
                "200": {
                  "$ref": "#/components/responses/confazCestList"
                }
              }
            },
            "put": {
              "tags": [
                "confazCest"
              ],
              "description": "CRUD put operation over confazCest",
              "operationId": "zzz_put_confazCest",
              "parameters": [
                {
                  "$ref": "#/components/parameters/confazCest"
                }
              ],
              "requestBody": {
                "$ref": "#/components/requestBodies/confazCest"
              },
              "responses": {
                "default": {
                  "$ref": "#/components/responses/Error"
                },
                "200": {
                  "$ref": "#/components/responses/confazCest"
                }
              }
            },
            "post": {
              "tags": [
                "confazCest"
              ],
              "description": "CRUD post operation over confazCest",
              "operationId": "zzz_post_confazCest",
              "requestBody": {
                "$ref": "#/components/requestBodies/confazCest"
              },
              "responses": {
                "default": {
                  "$ref": "#/components/responses/Error"
                },
                "200": {
                  "$ref": "#/components/responses/confazCest"
                }
              }
            },
            "delete": {
              "tags": [
                "confazCest"
              ],
              "description": "CRUD delete operation over confazCest",
              "operationId": "zzz_delete_confazCest",
              "parameters": [
                {
                  "$ref": "#/components/parameters/confazCest"
                }
              ],
              "responses": {
                "default": {
                  "$ref": "#/components/responses/Error"
                },
                "200": {
                  "$ref": "#/components/responses/confazCest"
                }
              }
            },
            "patch": {
              "tags": [
                "confazCest"
              ],
              "description": "CRUD patch operation over confazCest",
              "operationId": "zzz_patch_confazCest",
              "parameters": [
                {
                  "$ref": "#/components/parameters/confazCest"
                }
              ],
              "requestBody": {
                "$ref": "#/components/requestBodies/confazCest"
              },
              "responses": {
                "default": {
                  "$ref": "#/components/responses/Error"
                },
                "200": {
                  "$ref": "#/components/responses/confazCest"
                }
              }
            }
          },
          "/employed": {
            "get": {
              "tags": [
                "employed"
              ],
              "description": "CRUD get operation over employed",
              "operationId": "zzz_get_employed",
              "parameters": [
                {
                  "$ref": "#/components/parameters/employed"
                }
              ],
              "responses": {
                "default": {
                  "$ref": "#/components/responses/Error"
                },
                "200": {
                  "$ref": "#/components/responses/employedList"
                }
              }
            },
            "put": {
              "tags": [
                "employed"
              ],
              "description": "CRUD put operation over employed",
              "operationId": "zzz_put_employed",
              "parameters": [
                {
                  "$ref": "#/components/parameters/employed"
                }
              ],
              "requestBody": {
                "$ref": "#/components/requestBodies/employed"
              },
              "responses": {
                "default": {
                  "$ref": "#/components/responses/Error"
                },
                "200": {
                  "$ref": "#/components/responses/employed"
                }
              }
            },
            "post": {
              "tags": [
                "employed"
              ],
              "description": "CRUD post operation over employed",
              "operationId": "zzz_post_employed",
              "requestBody": {
                "$ref": "#/components/requestBodies/employed"
              },
              "responses": {
                "default": {
                  "$ref": "#/components/responses/Error"
                },
                "200": {
                  "$ref": "#/components/responses/employed"
                }
              }
            },
            "delete": {
              "tags": [
                "employed"
              ],
              "description": "CRUD delete operation over employed",
              "operationId": "zzz_delete_employed",
              "parameters": [
                {
                  "$ref": "#/components/parameters/employed"
                }
              ],
              "responses": {
                "default": {
                  "$ref": "#/components/responses/Error"
                },
                "200": {
                  "$ref": "#/components/responses/employed"
                }
              }
            },
            "patch": {
              "tags": [
                "employed"
              ],
              "description": "CRUD patch operation over employed",
              "operationId": "zzz_patch_employed",
              "parameters": [
                {
                  "$ref": "#/components/parameters/employed"
                }
              ],
              "requestBody": {
                "$ref": "#/components/requestBodies/employed"
              },
              "responses": {
                "default": {
                  "$ref": "#/components/responses/Error"
                },
                "200": {
                  "$ref": "#/components/responses/employed"
                }
              }
            }
          },
          "/ibge_city": {
            "get": {
              "tags": [
                "ibgeCity"
              ],
              "description": "CRUD get operation over ibgeCity",
              "operationId": "zzz_get_ibgeCity",
              "parameters": [
                {
                  "$ref": "#/components/parameters/ibgeCity"
                }
              ],
              "responses": {
                "default": {
                  "$ref": "#/components/responses/Error"
                },
                "200": {
                  "$ref": "#/components/responses/ibgeCityList"
                }
              }
            },
            "put": {
              "tags": [
                "ibgeCity"
              ],
              "description": "CRUD put operation over ibgeCity",
              "operationId": "zzz_put_ibgeCity",
              "parameters": [
                {
                  "$ref": "#/components/parameters/ibgeCity"
                }
              ],
              "requestBody": {
                "$ref": "#/components/requestBodies/ibgeCity"
              },
              "responses": {
                "default": {
                  "$ref": "#/components/responses/Error"
                },
                "200": {
                  "$ref": "#/components/responses/ibgeCity"
                }
              }
            },
            "post": {
              "tags": [
                "ibgeCity"
              ],
              "description": "CRUD post operation over ibgeCity",
              "operationId": "zzz_post_ibgeCity",
              "requestBody": {
                "$ref": "#/components/requestBodies/ibgeCity"
              },
              "responses": {
                "default": {
                  "$ref": "#/components/responses/Error"
                },
                "200": {
                  "$ref": "#/components/responses/ibgeCity"
                }
              }
            },
            "delete": {
              "tags": [
                "ibgeCity"
              ],
              "description": "CRUD delete operation over ibgeCity",
              "operationId": "zzz_delete_ibgeCity",
              "parameters": [
                {
                  "$ref": "#/components/parameters/ibgeCity"
                }
              ],
              "responses": {
                "default": {
                  "$ref": "#/components/responses/Error"
                },
                "200": {
                  "$ref": "#/components/responses/ibgeCity"
                }
              }
            },
            "patch": {
              "tags": [
                "ibgeCity"
              ],
              "description": "CRUD patch operation over ibgeCity",
              "operationId": "zzz_patch_ibgeCity",
              "parameters": [
                {
                  "$ref": "#/components/parameters/ibgeCity"
                }
              ],
              "requestBody": {
                "$ref": "#/components/requestBodies/ibgeCity"
              },
              "responses": {
                "default": {
                  "$ref": "#/components/responses/Error"
                },
                "200": {
                  "$ref": "#/components/responses/ibgeCity"
                }
              }
            }
          },
          "/ibge_cnae": {
            "get": {
              "tags": [
                "ibgeCnae"
              ],
              "description": "CRUD get operation over ibgeCnae",
              "operationId": "zzz_get_ibgeCnae",
              "parameters": [
                {
                  "$ref": "#/components/parameters/ibgeCnae"
                }
              ],
              "responses": {
                "default": {
                  "$ref": "#/components/responses/Error"
                },
                "200": {
                  "$ref": "#/components/responses/ibgeCnaeList"
                }
              }
            },
            "put": {
              "tags": [
                "ibgeCnae"
              ],
              "description": "CRUD put operation over ibgeCnae",
              "operationId": "zzz_put_ibgeCnae",
              "parameters": [
                {
                  "$ref": "#/components/parameters/ibgeCnae"
                }
              ],
              "requestBody": {
                "$ref": "#/components/requestBodies/ibgeCnae"
              },
              "responses": {
                "default": {
                  "$ref": "#/components/responses/Error"
                },
                "200": {
                  "$ref": "#/components/responses/ibgeCnae"
                }
              }
            },
            "post": {
              "tags": [
                "ibgeCnae"
              ],
              "description": "CRUD post operation over ibgeCnae",
              "operationId": "zzz_post_ibgeCnae",
              "requestBody": {
                "$ref": "#/components/requestBodies/ibgeCnae"
              },
              "responses": {
                "default": {
                  "$ref": "#/components/responses/Error"
                },
                "200": {
                  "$ref": "#/components/responses/ibgeCnae"
                }
              }
            },
            "delete": {
              "tags": [
                "ibgeCnae"
              ],
              "description": "CRUD delete operation over ibgeCnae",
              "operationId": "zzz_delete_ibgeCnae",
              "parameters": [
                {
                  "$ref": "#/components/parameters/ibgeCnae"
                }
              ],
              "responses": {
                "default": {
                  "$ref": "#/components/responses/Error"
                },
                "200": {
                  "$ref": "#/components/responses/ibgeCnae"
                }
              }
            },
            "patch": {
              "tags": [
                "ibgeCnae"
              ],
              "description": "CRUD patch operation over ibgeCnae",
              "operationId": "zzz_patch_ibgeCnae",
              "parameters": [
                {
                  "$ref": "#/components/parameters/ibgeCnae"
                }
              ],
              "requestBody": {
                "$ref": "#/components/requestBodies/ibgeCnae"
              },
              "responses": {
                "default": {
                  "$ref": "#/components/responses/Error"
                },
                "200": {
                  "$ref": "#/components/responses/ibgeCnae"
                }
              }
            }
          },
          "/ibge_uf": {
            "get": {
              "tags": [
                "ibgeUf"
              ],
              "description": "CRUD get operation over ibgeUf",
              "operationId": "zzz_get_ibgeUf",
              "parameters": [
                {
                  "$ref": "#/components/parameters/ibgeUf"
                }
              ],
              "responses": {
                "default": {
                  "$ref": "#/components/responses/Error"
                },
                "200": {
                  "$ref": "#/components/responses/ibgeUfList"
                }
              }
            },
            "put": {
              "tags": [
                "ibgeUf"
              ],
              "description": "CRUD put operation over ibgeUf",
              "operationId": "zzz_put_ibgeUf",
              "parameters": [
                {
                  "$ref": "#/components/parameters/ibgeUf"
                }
              ],
              "requestBody": {
                "$ref": "#/components/requestBodies/ibgeUf"
              },
              "responses": {
                "default": {
                  "$ref": "#/components/responses/Error"
                },
                "200": {
                  "$ref": "#/components/responses/ibgeUf"
                }
              }
            },
            "post": {
              "tags": [
                "ibgeUf"
              ],
              "description": "CRUD post operation over ibgeUf",
              "operationId": "zzz_post_ibgeUf",
              "requestBody": {
                "$ref": "#/components/requestBodies/ibgeUf"
              },
              "responses": {
                "default": {
                  "$ref": "#/components/responses/Error"
                },
                "200": {
                  "$ref": "#/components/responses/ibgeUf"
                }
              }
            },
            "delete": {
              "tags": [
                "ibgeUf"
              ],
              "description": "CRUD delete operation over ibgeUf",
              "operationId": "zzz_delete_ibgeUf",
              "parameters": [
                {
                  "$ref": "#/components/parameters/ibgeUf"
                }
              ],
              "responses": {
                "default": {
                  "$ref": "#/components/responses/Error"
                },
                "200": {
                  "$ref": "#/components/responses/ibgeUf"
                }
              }
            },
            "patch": {
              "tags": [
                "ibgeUf"
              ],
              "description": "CRUD patch operation over ibgeUf",
              "operationId": "zzz_patch_ibgeUf",
              "parameters": [
                {
                  "$ref": "#/components/parameters/ibgeUf"
                }
              ],
              "requestBody": {
                "$ref": "#/components/requestBodies/ibgeUf"
              },
              "responses": {
                "default": {
                  "$ref": "#/components/responses/Error"
                },
                "200": {
                  "$ref": "#/components/responses/ibgeUf"
                }
              }
            }
          },
          "/nfe_cfop": {
            "get": {
              "tags": [
                "nfeCfop"
              ],
              "description": "CRUD get operation over nfeCfop",
              "operationId": "zzz_get_nfeCfop",
              "parameters": [
                {
                  "$ref": "#/components/parameters/nfeCfop"
                }
              ],
              "responses": {
                "default": {
                  "$ref": "#/components/responses/Error"
                },
                "200": {
                  "$ref": "#/components/responses/nfeCfopList"
                }
              }
            },
            "put": {
              "tags": [
                "nfeCfop"
              ],
              "description": "CRUD put operation over nfeCfop",
              "operationId": "zzz_put_nfeCfop",
              "parameters": [
                {
                  "$ref": "#/components/parameters/nfeCfop"
                }
              ],
              "requestBody": {
                "$ref": "#/components/requestBodies/nfeCfop"
              },
              "responses": {
                "default": {
                  "$ref": "#/components/responses/Error"
                },
                "200": {
                  "$ref": "#/components/responses/nfeCfop"
                }
              }
            },
            "post": {
              "tags": [
                "nfeCfop"
              ],
              "description": "CRUD post operation over nfeCfop",
              "operationId": "zzz_post_nfeCfop",
              "requestBody": {
                "$ref": "#/components/requestBodies/nfeCfop"
              },
              "responses": {
                "default": {
                  "$ref": "#/components/responses/Error"
                },
                "200": {
                  "$ref": "#/components/responses/nfeCfop"
                }
              }
            },
            "delete": {
              "tags": [
                "nfeCfop"
              ],
              "description": "CRUD delete operation over nfeCfop",
              "operationId": "zzz_delete_nfeCfop",
              "parameters": [
                {
                  "$ref": "#/components/parameters/nfeCfop"
                }
              ],
              "responses": {
                "default": {
                  "$ref": "#/components/responses/Error"
                },
                "200": {
                  "$ref": "#/components/responses/nfeCfop"
                }
              }
            },
            "patch": {
              "tags": [
                "nfeCfop"
              ],
              "description": "CRUD patch operation over nfeCfop",
              "operationId": "zzz_patch_nfeCfop",
              "parameters": [
                {
                  "$ref": "#/components/parameters/nfeCfop"
                }
              ],
              "requestBody": {
                "$ref": "#/components/requestBodies/nfeCfop"
              },
              "responses": {
                "default": {
                  "$ref": "#/components/responses/Error"
                },
                "200": {
                  "$ref": "#/components/responses/nfeCfop"
                }
              }
            }
          },
          "/nfe_st_cofins": {
            "get": {
              "tags": [
                "nfeStCofins"
              ],
              "description": "CRUD get operation over nfeStCofins",
              "operationId": "zzz_get_nfeStCofins",
              "parameters": [
                {
                  "$ref": "#/components/parameters/nfeStCofins"
                }
              ],
              "responses": {
                "default": {
                  "$ref": "#/components/responses/Error"
                },
                "200": {
                  "$ref": "#/components/responses/nfeStCofinsList"
                }
              }
            },
            "put": {
              "tags": [
                "nfeStCofins"
              ],
              "description": "CRUD put operation over nfeStCofins",
              "operationId": "zzz_put_nfeStCofins",
              "parameters": [
                {
                  "$ref": "#/components/parameters/nfeStCofins"
                }
              ],
              "requestBody": {
                "$ref": "#/components/requestBodies/nfeStCofins"
              },
              "responses": {
                "default": {
                  "$ref": "#/components/responses/Error"
                },
                "200": {
                  "$ref": "#/components/responses/nfeStCofins"
                }
              }
            },
            "post": {
              "tags": [
                "nfeStCofins"
              ],
              "description": "CRUD post operation over nfeStCofins",
              "operationId": "zzz_post_nfeStCofins",
              "requestBody": {
                "$ref": "#/components/requestBodies/nfeStCofins"
              },
              "responses": {
                "default": {
                  "$ref": "#/components/responses/Error"
                },
                "200": {
                  "$ref": "#/components/responses/nfeStCofins"
                }
              }
            },
            "delete": {
              "tags": [
                "nfeStCofins"
              ],
              "description": "CRUD delete operation over nfeStCofins",
              "operationId": "zzz_delete_nfeStCofins",
              "parameters": [
                {
                  "$ref": "#/components/parameters/nfeStCofins"
                }
              ],
              "responses": {
                "default": {
                  "$ref": "#/components/responses/Error"
                },
                "200": {
                  "$ref": "#/components/responses/nfeStCofins"
                }
              }
            },
            "patch": {
              "tags": [
                "nfeStCofins"
              ],
              "description": "CRUD patch operation over nfeStCofins",
              "operationId": "zzz_patch_nfeStCofins",
              "parameters": [
                {
                  "$ref": "#/components/parameters/nfeStCofins"
                }
              ],
              "requestBody": {
                "$ref": "#/components/requestBodies/nfeStCofins"
              },
              "responses": {
                "default": {
                  "$ref": "#/components/responses/Error"
                },
                "200": {
                  "$ref": "#/components/responses/nfeStCofins"
                }
              }
            }
          },
          "/nfe_st_csosn": {
            "get": {
              "tags": [
                "nfeStCsosn"
              ],
              "description": "CRUD get operation over nfeStCsosn",
              "operationId": "zzz_get_nfeStCsosn",
              "parameters": [
                {
                  "$ref": "#/components/parameters/nfeStCsosn"
                }
              ],
              "responses": {
                "default": {
                  "$ref": "#/components/responses/Error"
                },
                "200": {
                  "$ref": "#/components/responses/nfeStCsosnList"
                }
              }
            },
            "put": {
              "tags": [
                "nfeStCsosn"
              ],
              "description": "CRUD put operation over nfeStCsosn",
              "operationId": "zzz_put_nfeStCsosn",
              "parameters": [
                {
                  "$ref": "#/components/parameters/nfeStCsosn"
                }
              ],
              "requestBody": {
                "$ref": "#/components/requestBodies/nfeStCsosn"
              },
              "responses": {
                "default": {
                  "$ref": "#/components/responses/Error"
                },
                "200": {
                  "$ref": "#/components/responses/nfeStCsosn"
                }
              }
            },
            "post": {
              "tags": [
                "nfeStCsosn"
              ],
              "description": "CRUD post operation over nfeStCsosn",
              "operationId": "zzz_post_nfeStCsosn",
              "requestBody": {
                "$ref": "#/components/requestBodies/nfeStCsosn"
              },
              "responses": {
                "default": {
                  "$ref": "#/components/responses/Error"
                },
                "200": {
                  "$ref": "#/components/responses/nfeStCsosn"
                }
              }
            },
            "delete": {
              "tags": [
                "nfeStCsosn"
              ],
              "description": "CRUD delete operation over nfeStCsosn",
              "operationId": "zzz_delete_nfeStCsosn",
              "parameters": [
                {
                  "$ref": "#/components/parameters/nfeStCsosn"
                }
              ],
              "responses": {
                "default": {
                  "$ref": "#/components/responses/Error"
                },
                "200": {
                  "$ref": "#/components/responses/nfeStCsosn"
                }
              }
            },
            "patch": {
              "tags": [
                "nfeStCsosn"
              ],
              "description": "CRUD patch operation over nfeStCsosn",
              "operationId": "zzz_patch_nfeStCsosn",
              "parameters": [
                {
                  "$ref": "#/components/parameters/nfeStCsosn"
                }
              ],
              "requestBody": {
                "$ref": "#/components/requestBodies/nfeStCsosn"
              },
              "responses": {
                "default": {
                  "$ref": "#/components/responses/Error"
                },
                "200": {
                  "$ref": "#/components/responses/nfeStCsosn"
                }
              }
            }
          },
          "/nfe_st_icms": {
            "get": {
              "tags": [
                "nfeStIcms"
              ],
              "description": "CRUD get operation over nfeStIcms",
              "operationId": "zzz_get_nfeStIcms",
              "parameters": [
                {
                  "$ref": "#/components/parameters/nfeStIcms"
                }
              ],
              "responses": {
                "default": {
                  "$ref": "#/components/responses/Error"
                },
                "200": {
                  "$ref": "#/components/responses/nfeStIcmsList"
                }
              }
            },
            "put": {
              "tags": [
                "nfeStIcms"
              ],
              "description": "CRUD put operation over nfeStIcms",
              "operationId": "zzz_put_nfeStIcms",
              "parameters": [
                {
                  "$ref": "#/components/parameters/nfeStIcms"
                }
              ],
              "requestBody": {
                "$ref": "#/components/requestBodies/nfeStIcms"
              },
              "responses": {
                "default": {
                  "$ref": "#/components/responses/Error"
                },
                "200": {
                  "$ref": "#/components/responses/nfeStIcms"
                }
              }
            },
            "post": {
              "tags": [
                "nfeStIcms"
              ],
              "description": "CRUD post operation over nfeStIcms",
              "operationId": "zzz_post_nfeStIcms",
              "requestBody": {
                "$ref": "#/components/requestBodies/nfeStIcms"
              },
              "responses": {
                "default": {
                  "$ref": "#/components/responses/Error"
                },
                "200": {
                  "$ref": "#/components/responses/nfeStIcms"
                }
              }
            },
            "delete": {
              "tags": [
                "nfeStIcms"
              ],
              "description": "CRUD delete operation over nfeStIcms",
              "operationId": "zzz_delete_nfeStIcms",
              "parameters": [
                {
                  "$ref": "#/components/parameters/nfeStIcms"
                }
              ],
              "responses": {
                "default": {
                  "$ref": "#/components/responses/Error"
                },
                "200": {
                  "$ref": "#/components/responses/nfeStIcms"
                }
              }
            },
            "patch": {
              "tags": [
                "nfeStIcms"
              ],
              "description": "CRUD patch operation over nfeStIcms",
              "operationId": "zzz_patch_nfeStIcms",
              "parameters": [
                {
                  "$ref": "#/components/parameters/nfeStIcms"
                }
              ],
              "requestBody": {
                "$ref": "#/components/requestBodies/nfeStIcms"
              },
              "responses": {
                "default": {
                  "$ref": "#/components/responses/Error"
                },
                "200": {
                  "$ref": "#/components/responses/nfeStIcms"
                }
              }
            }
          },
          "/nfe_st_icms_desoneracao": {
            "get": {
              "tags": [
                "nfeStIcmsDesoneracao"
              ],
              "description": "CRUD get operation over nfeStIcmsDesoneracao",
              "operationId": "zzz_get_nfeStIcmsDesoneracao",
              "parameters": [
                {
                  "$ref": "#/components/parameters/nfeStIcmsDesoneracao"
                }
              ],
              "responses": {
                "default": {
                  "$ref": "#/components/responses/Error"
                },
                "200": {
                  "$ref": "#/components/responses/nfeStIcmsDesoneracaoList"
                }
              }
            },
            "put": {
              "tags": [
                "nfeStIcmsDesoneracao"
              ],
              "description": "CRUD put operation over nfeStIcmsDesoneracao",
              "operationId": "zzz_put_nfeStIcmsDesoneracao",
              "parameters": [
                {
                  "$ref": "#/components/parameters/nfeStIcmsDesoneracao"
                }
              ],
              "requestBody": {
                "$ref": "#/components/requestBodies/nfeStIcmsDesoneracao"
              },
              "responses": {
                "default": {
                  "$ref": "#/components/responses/Error"
                },
                "200": {
                  "$ref": "#/components/responses/nfeStIcmsDesoneracao"
                }
              }
            },
            "post": {
              "tags": [
                "nfeStIcmsDesoneracao"
              ],
              "description": "CRUD post operation over nfeStIcmsDesoneracao",
              "operationId": "zzz_post_nfeStIcmsDesoneracao",
              "requestBody": {
                "$ref": "#/components/requestBodies/nfeStIcmsDesoneracao"
              },
              "responses": {
                "default": {
                  "$ref": "#/components/responses/Error"
                },
                "200": {
                  "$ref": "#/components/responses/nfeStIcmsDesoneracao"
                }
              }
            },
            "delete": {
              "tags": [
                "nfeStIcmsDesoneracao"
              ],
              "description": "CRUD delete operation over nfeStIcmsDesoneracao",
              "operationId": "zzz_delete_nfeStIcmsDesoneracao",
              "parameters": [
                {
                  "$ref": "#/components/parameters/nfeStIcmsDesoneracao"
                }
              ],
              "responses": {
                "default": {
                  "$ref": "#/components/responses/Error"
                },
                "200": {
                  "$ref": "#/components/responses/nfeStIcmsDesoneracao"
                }
              }
            },
            "patch": {
              "tags": [
                "nfeStIcmsDesoneracao"
              ],
              "description": "CRUD patch operation over nfeStIcmsDesoneracao",
              "operationId": "zzz_patch_nfeStIcmsDesoneracao",
              "parameters": [
                {
                  "$ref": "#/components/parameters/nfeStIcmsDesoneracao"
                }
              ],
              "requestBody": {
                "$ref": "#/components/requestBodies/nfeStIcmsDesoneracao"
              },
              "responses": {
                "default": {
                  "$ref": "#/components/responses/Error"
                },
                "200": {
                  "$ref": "#/components/responses/nfeStIcmsDesoneracao"
                }
              }
            }
          },
          "/nfe_st_icms_modalidade_bc": {
            "get": {
              "tags": [
                "nfeStIcmsModalidadeBc"
              ],
              "description": "CRUD get operation over nfeStIcmsModalidadeBc",
              "operationId": "zzz_get_nfeStIcmsModalidadeBc",
              "parameters": [
                {
                  "$ref": "#/components/parameters/nfeStIcmsModalidadeBc"
                }
              ],
              "responses": {
                "default": {
                  "$ref": "#/components/responses/Error"
                },
                "200": {
                  "$ref": "#/components/responses/nfeStIcmsModalidadeBcList"
                }
              }
            },
            "put": {
              "tags": [
                "nfeStIcmsModalidadeBc"
              ],
              "description": "CRUD put operation over nfeStIcmsModalidadeBc",
              "operationId": "zzz_put_nfeStIcmsModalidadeBc",
              "parameters": [
                {
                  "$ref": "#/components/parameters/nfeStIcmsModalidadeBc"
                }
              ],
              "requestBody": {
                "$ref": "#/components/requestBodies/nfeStIcmsModalidadeBc"
              },
              "responses": {
                "default": {
                  "$ref": "#/components/responses/Error"
                },
                "200": {
                  "$ref": "#/components/responses/nfeStIcmsModalidadeBc"
                }
              }
            },
            "post": {
              "tags": [
                "nfeStIcmsModalidadeBc"
              ],
              "description": "CRUD post operation over nfeStIcmsModalidadeBc",
              "operationId": "zzz_post_nfeStIcmsModalidadeBc",
              "requestBody": {
                "$ref": "#/components/requestBodies/nfeStIcmsModalidadeBc"
              },
              "responses": {
                "default": {
                  "$ref": "#/components/responses/Error"
                },
                "200": {
                  "$ref": "#/components/responses/nfeStIcmsModalidadeBc"
                }
              }
            },
            "delete": {
              "tags": [
                "nfeStIcmsModalidadeBc"
              ],
              "description": "CRUD delete operation over nfeStIcmsModalidadeBc",
              "operationId": "zzz_delete_nfeStIcmsModalidadeBc",
              "parameters": [
                {
                  "$ref": "#/components/parameters/nfeStIcmsModalidadeBc"
                }
              ],
              "responses": {
                "default": {
                  "$ref": "#/components/responses/Error"
                },
                "200": {
                  "$ref": "#/components/responses/nfeStIcmsModalidadeBc"
                }
              }
            },
            "patch": {
              "tags": [
                "nfeStIcmsModalidadeBc"
              ],
              "description": "CRUD patch operation over nfeStIcmsModalidadeBc",
              "operationId": "zzz_patch_nfeStIcmsModalidadeBc",
              "parameters": [
                {
                  "$ref": "#/components/parameters/nfeStIcmsModalidadeBc"
                }
              ],
              "requestBody": {
                "$ref": "#/components/requestBodies/nfeStIcmsModalidadeBc"
              },
              "responses": {
                "default": {
                  "$ref": "#/components/responses/Error"
                },
                "200": {
                  "$ref": "#/components/responses/nfeStIcmsModalidadeBc"
                }
              }
            }
          },
          "/nfe_st_icms_modalidade_st": {
            "get": {
              "tags": [
                "nfeStIcmsModalidadeSt"
              ],
              "description": "CRUD get operation over nfeStIcmsModalidadeSt",
              "operationId": "zzz_get_nfeStIcmsModalidadeSt",
              "parameters": [
                {
                  "$ref": "#/components/parameters/nfeStIcmsModalidadeSt"
                }
              ],
              "responses": {
                "default": {
                  "$ref": "#/components/responses/Error"
                },
                "200": {
                  "$ref": "#/components/responses/nfeStIcmsModalidadeStList"
                }
              }
            },
            "put": {
              "tags": [
                "nfeStIcmsModalidadeSt"
              ],
              "description": "CRUD put operation over nfeStIcmsModalidadeSt",
              "operationId": "zzz_put_nfeStIcmsModalidadeSt",
              "parameters": [
                {
                  "$ref": "#/components/parameters/nfeStIcmsModalidadeSt"
                }
              ],
              "requestBody": {
                "$ref": "#/components/requestBodies/nfeStIcmsModalidadeSt"
              },
              "responses": {
                "default": {
                  "$ref": "#/components/responses/Error"
                },
                "200": {
                  "$ref": "#/components/responses/nfeStIcmsModalidadeSt"
                }
              }
            },
            "post": {
              "tags": [
                "nfeStIcmsModalidadeSt"
              ],
              "description": "CRUD post operation over nfeStIcmsModalidadeSt",
              "operationId": "zzz_post_nfeStIcmsModalidadeSt",
              "requestBody": {
                "$ref": "#/components/requestBodies/nfeStIcmsModalidadeSt"
              },
              "responses": {
                "default": {
                  "$ref": "#/components/responses/Error"
                },
                "200": {
                  "$ref": "#/components/responses/nfeStIcmsModalidadeSt"
                }
              }
            },
            "delete": {
              "tags": [
                "nfeStIcmsModalidadeSt"
              ],
              "description": "CRUD delete operation over nfeStIcmsModalidadeSt",
              "operationId": "zzz_delete_nfeStIcmsModalidadeSt",
              "parameters": [
                {
                  "$ref": "#/components/parameters/nfeStIcmsModalidadeSt"
                }
              ],
              "responses": {
                "default": {
                  "$ref": "#/components/responses/Error"
                },
                "200": {
                  "$ref": "#/components/responses/nfeStIcmsModalidadeSt"
                }
              }
            },
            "patch": {
              "tags": [
                "nfeStIcmsModalidadeSt"
              ],
              "description": "CRUD patch operation over nfeStIcmsModalidadeSt",
              "operationId": "zzz_patch_nfeStIcmsModalidadeSt",
              "parameters": [
                {
                  "$ref": "#/components/parameters/nfeStIcmsModalidadeSt"
                }
              ],
              "requestBody": {
                "$ref": "#/components/requestBodies/nfeStIcmsModalidadeSt"
              },
              "responses": {
                "default": {
                  "$ref": "#/components/responses/Error"
                },
                "200": {
                  "$ref": "#/components/responses/nfeStIcmsModalidadeSt"
                }
              }
            }
          },
          "/nfe_st_icms_origem": {
            "get": {
              "tags": [
                "nfeStIcmsOrigem"
              ],
              "description": "CRUD get operation over nfeStIcmsOrigem",
              "operationId": "zzz_get_nfeStIcmsOrigem",
              "parameters": [
                {
                  "$ref": "#/components/parameters/nfeStIcmsOrigem"
                }
              ],
              "responses": {
                "default": {
                  "$ref": "#/components/responses/Error"
                },
                "200": {
                  "$ref": "#/components/responses/nfeStIcmsOrigemList"
                }
              }
            },
            "put": {
              "tags": [
                "nfeStIcmsOrigem"
              ],
              "description": "CRUD put operation over nfeStIcmsOrigem",
              "operationId": "zzz_put_nfeStIcmsOrigem",
              "parameters": [
                {
                  "$ref": "#/components/parameters/nfeStIcmsOrigem"
                }
              ],
              "requestBody": {
                "$ref": "#/components/requestBodies/nfeStIcmsOrigem"
              },
              "responses": {
                "default": {
                  "$ref": "#/components/responses/Error"
                },
                "200": {
                  "$ref": "#/components/responses/nfeStIcmsOrigem"
                }
              }
            },
            "post": {
              "tags": [
                "nfeStIcmsOrigem"
              ],
              "description": "CRUD post operation over nfeStIcmsOrigem",
              "operationId": "zzz_post_nfeStIcmsOrigem",
              "requestBody": {
                "$ref": "#/components/requestBodies/nfeStIcmsOrigem"
              },
              "responses": {
                "default": {
                  "$ref": "#/components/responses/Error"
                },
                "200": {
                  "$ref": "#/components/responses/nfeStIcmsOrigem"
                }
              }
            },
            "delete": {
              "tags": [
                "nfeStIcmsOrigem"
              ],
              "description": "CRUD delete operation over nfeStIcmsOrigem",
              "operationId": "zzz_delete_nfeStIcmsOrigem",
              "parameters": [
                {
                  "$ref": "#/components/parameters/nfeStIcmsOrigem"
                }
              ],
              "responses": {
                "default": {
                  "$ref": "#/components/responses/Error"
                },
                "200": {
                  "$ref": "#/components/responses/nfeStIcmsOrigem"
                }
              }
            },
            "patch": {
              "tags": [
                "nfeStIcmsOrigem"
              ],
              "description": "CRUD patch operation over nfeStIcmsOrigem",
              "operationId": "zzz_patch_nfeStIcmsOrigem",
              "parameters": [
                {
                  "$ref": "#/components/parameters/nfeStIcmsOrigem"
                }
              ],
              "requestBody": {
                "$ref": "#/components/requestBodies/nfeStIcmsOrigem"
              },
              "responses": {
                "default": {
                  "$ref": "#/components/responses/Error"
                },
                "200": {
                  "$ref": "#/components/responses/nfeStIcmsOrigem"
                }
              }
            }
          },
          "/nfe_st_ipi": {
            "get": {
              "tags": [
                "nfeStIpi"
              ],
              "description": "CRUD get operation over nfeStIpi",
              "operationId": "zzz_get_nfeStIpi",
              "parameters": [
                {
                  "$ref": "#/components/parameters/nfeStIpi"
                }
              ],
              "responses": {
                "default": {
                  "$ref": "#/components/responses/Error"
                },
                "200": {
                  "$ref": "#/components/responses/nfeStIpiList"
                }
              }
            },
            "put": {
              "tags": [
                "nfeStIpi"
              ],
              "description": "CRUD put operation over nfeStIpi",
              "operationId": "zzz_put_nfeStIpi",
              "parameters": [
                {
                  "$ref": "#/components/parameters/nfeStIpi"
                }
              ],
              "requestBody": {
                "$ref": "#/components/requestBodies/nfeStIpi"
              },
              "responses": {
                "default": {
                  "$ref": "#/components/responses/Error"
                },
                "200": {
                  "$ref": "#/components/responses/nfeStIpi"
                }
              }
            },
            "post": {
              "tags": [
                "nfeStIpi"
              ],
              "description": "CRUD post operation over nfeStIpi",
              "operationId": "zzz_post_nfeStIpi",
              "requestBody": {
                "$ref": "#/components/requestBodies/nfeStIpi"
              },
              "responses": {
                "default": {
                  "$ref": "#/components/responses/Error"
                },
                "200": {
                  "$ref": "#/components/responses/nfeStIpi"
                }
              }
            },
            "delete": {
              "tags": [
                "nfeStIpi"
              ],
              "description": "CRUD delete operation over nfeStIpi",
              "operationId": "zzz_delete_nfeStIpi",
              "parameters": [
                {
                  "$ref": "#/components/parameters/nfeStIpi"
                }
              ],
              "responses": {
                "default": {
                  "$ref": "#/components/responses/Error"
                },
                "200": {
                  "$ref": "#/components/responses/nfeStIpi"
                }
              }
            },
            "patch": {
              "tags": [
                "nfeStIpi"
              ],
              "description": "CRUD patch operation over nfeStIpi",
              "operationId": "zzz_patch_nfeStIpi",
              "parameters": [
                {
                  "$ref": "#/components/parameters/nfeStIpi"
                }
              ],
              "requestBody": {
                "$ref": "#/components/requestBodies/nfeStIpi"
              },
              "responses": {
                "default": {
                  "$ref": "#/components/responses/Error"
                },
                "200": {
                  "$ref": "#/components/responses/nfeStIpi"
                }
              }
            }
          },
          "/nfe_st_ipi_enquadramento": {
            "get": {
              "tags": [
                "nfeStIpiEnquadramento"
              ],
              "description": "CRUD get operation over nfeStIpiEnquadramento",
              "operationId": "zzz_get_nfeStIpiEnquadramento",
              "parameters": [
                {
                  "$ref": "#/components/parameters/nfeStIpiEnquadramento"
                }
              ],
              "responses": {
                "default": {
                  "$ref": "#/components/responses/Error"
                },
                "200": {
                  "$ref": "#/components/responses/nfeStIpiEnquadramentoList"
                }
              }
            },
            "put": {
              "tags": [
                "nfeStIpiEnquadramento"
              ],
              "description": "CRUD put operation over nfeStIpiEnquadramento",
              "operationId": "zzz_put_nfeStIpiEnquadramento",
              "parameters": [
                {
                  "$ref": "#/components/parameters/nfeStIpiEnquadramento"
                }
              ],
              "requestBody": {
                "$ref": "#/components/requestBodies/nfeStIpiEnquadramento"
              },
              "responses": {
                "default": {
                  "$ref": "#/components/responses/Error"
                },
                "200": {
                  "$ref": "#/components/responses/nfeStIpiEnquadramento"
                }
              }
            },
            "post": {
              "tags": [
                "nfeStIpiEnquadramento"
              ],
              "description": "CRUD post operation over nfeStIpiEnquadramento",
              "operationId": "zzz_post_nfeStIpiEnquadramento",
              "requestBody": {
                "$ref": "#/components/requestBodies/nfeStIpiEnquadramento"
              },
              "responses": {
                "default": {
                  "$ref": "#/components/responses/Error"
                },
                "200": {
                  "$ref": "#/components/responses/nfeStIpiEnquadramento"
                }
              }
            },
            "delete": {
              "tags": [
                "nfeStIpiEnquadramento"
              ],
              "description": "CRUD delete operation over nfeStIpiEnquadramento",
              "operationId": "zzz_delete_nfeStIpiEnquadramento",
              "parameters": [
                {
                  "$ref": "#/components/parameters/nfeStIpiEnquadramento"
                }
              ],
              "responses": {
                "default": {
                  "$ref": "#/components/responses/Error"
                },
                "200": {
                  "$ref": "#/components/responses/nfeStIpiEnquadramento"
                }
              }
            },
            "patch": {
              "tags": [
                "nfeStIpiEnquadramento"
              ],
              "description": "CRUD patch operation over nfeStIpiEnquadramento",
              "operationId": "zzz_patch_nfeStIpiEnquadramento",
              "parameters": [
                {
                  "$ref": "#/components/parameters/nfeStIpiEnquadramento"
                }
              ],
              "requestBody": {
                "$ref": "#/components/requestBodies/nfeStIpiEnquadramento"
              },
              "responses": {
                "default": {
                  "$ref": "#/components/responses/Error"
                },
                "200": {
                  "$ref": "#/components/responses/nfeStIpiEnquadramento"
                }
              }
            }
          },
          "/nfe_st_ipi_operacao": {
            "get": {
              "tags": [
                "nfeStIpiOperacao"
              ],
              "description": "CRUD get operation over nfeStIpiOperacao",
              "operationId": "zzz_get_nfeStIpiOperacao",
              "parameters": [
                {
                  "$ref": "#/components/parameters/nfeStIpiOperacao"
                }
              ],
              "responses": {
                "default": {
                  "$ref": "#/components/responses/Error"
                },
                "200": {
                  "$ref": "#/components/responses/nfeStIpiOperacaoList"
                }
              }
            },
            "put": {
              "tags": [
                "nfeStIpiOperacao"
              ],
              "description": "CRUD put operation over nfeStIpiOperacao",
              "operationId": "zzz_put_nfeStIpiOperacao",
              "parameters": [
                {
                  "$ref": "#/components/parameters/nfeStIpiOperacao"
                }
              ],
              "requestBody": {
                "$ref": "#/components/requestBodies/nfeStIpiOperacao"
              },
              "responses": {
                "default": {
                  "$ref": "#/components/responses/Error"
                },
                "200": {
                  "$ref": "#/components/responses/nfeStIpiOperacao"
                }
              }
            },
            "post": {
              "tags": [
                "nfeStIpiOperacao"
              ],
              "description": "CRUD post operation over nfeStIpiOperacao",
              "operationId": "zzz_post_nfeStIpiOperacao",
              "requestBody": {
                "$ref": "#/components/requestBodies/nfeStIpiOperacao"
              },
              "responses": {
                "default": {
                  "$ref": "#/components/responses/Error"
                },
                "200": {
                  "$ref": "#/components/responses/nfeStIpiOperacao"
                }
              }
            },
            "delete": {
              "tags": [
                "nfeStIpiOperacao"
              ],
              "description": "CRUD delete operation over nfeStIpiOperacao",
              "operationId": "zzz_delete_nfeStIpiOperacao",
              "parameters": [
                {
                  "$ref": "#/components/parameters/nfeStIpiOperacao"
                }
              ],
              "responses": {
                "default": {
                  "$ref": "#/components/responses/Error"
                },
                "200": {
                  "$ref": "#/components/responses/nfeStIpiOperacao"
                }
              }
            },
            "patch": {
              "tags": [
                "nfeStIpiOperacao"
              ],
              "description": "CRUD patch operation over nfeStIpiOperacao",
              "operationId": "zzz_patch_nfeStIpiOperacao",
              "parameters": [
                {
                  "$ref": "#/components/parameters/nfeStIpiOperacao"
                }
              ],
              "requestBody": {
                "$ref": "#/components/requestBodies/nfeStIpiOperacao"
              },
              "responses": {
                "default": {
                  "$ref": "#/components/responses/Error"
                },
                "200": {
                  "$ref": "#/components/responses/nfeStIpiOperacao"
                }
              }
            }
          },
          "/nfe_st_pis": {
            "get": {
              "tags": [
                "nfeStPis"
              ],
              "description": "CRUD get operation over nfeStPis",
              "operationId": "zzz_get_nfeStPis",
              "parameters": [
                {
                  "$ref": "#/components/parameters/nfeStPis"
                }
              ],
              "responses": {
                "default": {
                  "$ref": "#/components/responses/Error"
                },
                "200": {
                  "$ref": "#/components/responses/nfeStPisList"
                }
              }
            },
            "put": {
              "tags": [
                "nfeStPis"
              ],
              "description": "CRUD put operation over nfeStPis",
              "operationId": "zzz_put_nfeStPis",
              "parameters": [
                {
                  "$ref": "#/components/parameters/nfeStPis"
                }
              ],
              "requestBody": {
                "$ref": "#/components/requestBodies/nfeStPis"
              },
              "responses": {
                "default": {
                  "$ref": "#/components/responses/Error"
                },
                "200": {
                  "$ref": "#/components/responses/nfeStPis"
                }
              }
            },
            "post": {
              "tags": [
                "nfeStPis"
              ],
              "description": "CRUD post operation over nfeStPis",
              "operationId": "zzz_post_nfeStPis",
              "requestBody": {
                "$ref": "#/components/requestBodies/nfeStPis"
              },
              "responses": {
                "default": {
                  "$ref": "#/components/responses/Error"
                },
                "200": {
                  "$ref": "#/components/responses/nfeStPis"
                }
              }
            },
            "delete": {
              "tags": [
                "nfeStPis"
              ],
              "description": "CRUD delete operation over nfeStPis",
              "operationId": "zzz_delete_nfeStPis",
              "parameters": [
                {
                  "$ref": "#/components/parameters/nfeStPis"
                }
              ],
              "responses": {
                "default": {
                  "$ref": "#/components/responses/Error"
                },
                "200": {
                  "$ref": "#/components/responses/nfeStPis"
                }
              }
            },
            "patch": {
              "tags": [
                "nfeStPis"
              ],
              "description": "CRUD patch operation over nfeStPis",
              "operationId": "zzz_patch_nfeStPis",
              "parameters": [
                {
                  "$ref": "#/components/parameters/nfeStPis"
                }
              ],
              "requestBody": {
                "$ref": "#/components/requestBodies/nfeStPis"
              },
              "responses": {
                "default": {
                  "$ref": "#/components/responses/Error"
                },
                "200": {
                  "$ref": "#/components/responses/nfeStPis"
                }
              }
            }
          },
          "/nfe_tax_group": {
            "get": {
              "tags": [
                "nfeTaxGroup"
              ],
              "description": "CRUD get operation over nfeTaxGroup",
              "operationId": "zzz_get_nfeTaxGroup",
              "parameters": [
                {
                  "$ref": "#/components/parameters/nfeTaxGroup"
                }
              ],
              "responses": {
                "default": {
                  "$ref": "#/components/responses/Error"
                },
                "200": {
                  "$ref": "#/components/responses/nfeTaxGroupList"
                }
              }
            },
            "put": {
              "tags": [
                "nfeTaxGroup"
              ],
              "description": "CRUD put operation over nfeTaxGroup",
              "operationId": "zzz_put_nfeTaxGroup",
              "parameters": [
                {
                  "$ref": "#/components/parameters/nfeTaxGroup"
                }
              ],
              "requestBody": {
                "$ref": "#/components/requestBodies/nfeTaxGroup"
              },
              "responses": {
                "default": {
                  "$ref": "#/components/responses/Error"
                },
                "200": {
                  "$ref": "#/components/responses/nfeTaxGroup"
                }
              }
            },
            "post": {
              "tags": [
                "nfeTaxGroup"
              ],
              "description": "CRUD post operation over nfeTaxGroup",
              "operationId": "zzz_post_nfeTaxGroup",
              "requestBody": {
                "$ref": "#/components/requestBodies/nfeTaxGroup"
              },
              "responses": {
                "default": {
                  "$ref": "#/components/responses/Error"
                },
                "200": {
                  "$ref": "#/components/responses/nfeTaxGroup"
                }
              }
            },
            "delete": {
              "tags": [
                "nfeTaxGroup"
              ],
              "description": "CRUD delete operation over nfeTaxGroup",
              "operationId": "zzz_delete_nfeTaxGroup",
              "parameters": [
                {
                  "$ref": "#/components/parameters/nfeTaxGroup"
                }
              ],
              "responses": {
                "default": {
                  "$ref": "#/components/responses/Error"
                },
                "200": {
                  "$ref": "#/components/responses/nfeTaxGroup"
                }
              }
            },
            "patch": {
              "tags": [
                "nfeTaxGroup"
              ],
              "description": "CRUD patch operation over nfeTaxGroup",
              "operationId": "zzz_patch_nfeTaxGroup",
              "parameters": [
                {
                  "$ref": "#/components/parameters/nfeTaxGroup"
                }
              ],
              "requestBody": {
                "$ref": "#/components/requestBodies/nfeTaxGroup"
              },
              "responses": {
                "default": {
                  "$ref": "#/components/responses/Error"
                },
                "200": {
                  "$ref": "#/components/responses/nfeTaxGroup"
                }
              }
            }
          },
          "/nfse_cod_service": {
            "get": {
              "tags": [
                "nfseCodService"
              ],
              "description": "CRUD get operation over nfseCodService",
              "operationId": "zzz_get_nfseCodService",
              "parameters": [
                {
                  "$ref": "#/components/parameters/nfseCodService"
                }
              ],
              "responses": {
                "default": {
                  "$ref": "#/components/responses/Error"
                },
                "200": {
                  "$ref": "#/components/responses/nfseCodServiceList"
                }
              }
            },
            "put": {
              "tags": [
                "nfseCodService"
              ],
              "description": "CRUD put operation over nfseCodService",
              "operationId": "zzz_put_nfseCodService",
              "parameters": [
                {
                  "$ref": "#/components/parameters/nfseCodService"
                }
              ],
              "requestBody": {
                "$ref": "#/components/requestBodies/nfseCodService"
              },
              "responses": {
                "default": {
                  "$ref": "#/components/responses/Error"
                },
                "200": {
                  "$ref": "#/components/responses/nfseCodService"
                }
              }
            },
            "post": {
              "tags": [
                "nfseCodService"
              ],
              "description": "CRUD post operation over nfseCodService",
              "operationId": "zzz_post_nfseCodService",
              "requestBody": {
                "$ref": "#/components/requestBodies/nfseCodService"
              },
              "responses": {
                "default": {
                  "$ref": "#/components/responses/Error"
                },
                "200": {
                  "$ref": "#/components/responses/nfseCodService"
                }
              }
            },
            "delete": {
              "tags": [
                "nfseCodService"
              ],
              "description": "CRUD delete operation over nfseCodService",
              "operationId": "zzz_delete_nfseCodService",
              "parameters": [
                {
                  "$ref": "#/components/parameters/nfseCodService"
                }
              ],
              "responses": {
                "default": {
                  "$ref": "#/components/responses/Error"
                },
                "200": {
                  "$ref": "#/components/responses/nfseCodService"
                }
              }
            },
            "patch": {
              "tags": [
                "nfseCodService"
              ],
              "description": "CRUD patch operation over nfseCodService",
              "operationId": "zzz_patch_nfseCodService",
              "parameters": [
                {
                  "$ref": "#/components/parameters/nfseCodService"
                }
              ],
              "requestBody": {
                "$ref": "#/components/requestBodies/nfseCodService"
              },
              "responses": {
                "default": {
                  "$ref": "#/components/responses/Error"
                },
                "200": {
                  "$ref": "#/components/responses/nfseCodService"
                }
              }
            }
          },
          "/payment_type": {
            "get": {
              "tags": [
                "paymentType"
              ],
              "description": "CRUD get operation over paymentType",
              "operationId": "zzz_get_paymentType",
              "parameters": [
                {
                  "$ref": "#/components/parameters/paymentType"
                }
              ],
              "responses": {
                "default": {
                  "$ref": "#/components/responses/Error"
                },
                "200": {
                  "$ref": "#/components/responses/paymentTypeList"
                }
              }
            },
            "put": {
              "tags": [
                "paymentType"
              ],
              "description": "CRUD put operation over paymentType",
              "operationId": "zzz_put_paymentType",
              "parameters": [
                {
                  "$ref": "#/components/parameters/paymentType"
                }
              ],
              "requestBody": {
                "$ref": "#/components/requestBodies/paymentType"
              },
              "responses": {
                "default": {
                  "$ref": "#/components/responses/Error"
                },
                "200": {
                  "$ref": "#/components/responses/paymentType"
                }
              }
            },
            "post": {
              "tags": [
                "paymentType"
              ],
              "description": "CRUD post operation over paymentType",
              "operationId": "zzz_post_paymentType",
              "requestBody": {
                "$ref": "#/components/requestBodies/paymentType"
              },
              "responses": {
                "default": {
                  "$ref": "#/components/responses/Error"
                },
                "200": {
                  "$ref": "#/components/responses/paymentType"
                }
              }
            },
            "delete": {
              "tags": [
                "paymentType"
              ],
              "description": "CRUD delete operation over paymentType",
              "operationId": "zzz_delete_paymentType",
              "parameters": [
                {
                  "$ref": "#/components/parameters/paymentType"
                }
              ],
              "responses": {
                "default": {
                  "$ref": "#/components/responses/Error"
                },
                "200": {
                  "$ref": "#/components/responses/paymentType"
                }
              }
            },
            "patch": {
              "tags": [
                "paymentType"
              ],
              "description": "CRUD patch operation over paymentType",
              "operationId": "zzz_patch_paymentType",
              "parameters": [
                {
                  "$ref": "#/components/parameters/paymentType"
                }
              ],
              "requestBody": {
                "$ref": "#/components/requestBodies/paymentType"
              },
              "responses": {
                "default": {
                  "$ref": "#/components/responses/Error"
                },
                "200": {
                  "$ref": "#/components/responses/paymentType"
                }
              }
            }
          },
          "/person": {
            "get": {
              "tags": [
                "person"
              ],
              "description": "CRUD get operation over person",
              "operationId": "zzz_get_person",
              "parameters": [
                {
                  "$ref": "#/components/parameters/person"
                }
              ],
              "responses": {
                "default": {
                  "$ref": "#/components/responses/Error"
                },
                "200": {
                  "$ref": "#/components/responses/personList"
                }
              }
            },
            "put": {
              "tags": [
                "person"
              ],
              "description": "CRUD put operation over person",
              "operationId": "zzz_put_person",
              "parameters": [
                {
                  "$ref": "#/components/parameters/person"
                }
              ],
              "requestBody": {
                "$ref": "#/components/requestBodies/person"
              },
              "responses": {
                "default": {
                  "$ref": "#/components/responses/Error"
                },
                "200": {
                  "$ref": "#/components/responses/person"
                }
              }
            },
            "post": {
              "tags": [
                "person"
              ],
              "description": "CRUD post operation over person",
              "operationId": "zzz_post_person",
              "requestBody": {
                "$ref": "#/components/requestBodies/person"
              },
              "responses": {
                "default": {
                  "$ref": "#/components/responses/Error"
                },
                "200": {
                  "$ref": "#/components/responses/person"
                }
              }
            },
            "delete": {
              "tags": [
                "person"
              ],
              "description": "CRUD delete operation over person",
              "operationId": "zzz_delete_person",
              "parameters": [
                {
                  "$ref": "#/components/parameters/person"
                }
              ],
              "responses": {
                "default": {
                  "$ref": "#/components/responses/Error"
                },
                "200": {
                  "$ref": "#/components/responses/person"
                }
              }
            },
            "patch": {
              "tags": [
                "person"
              ],
              "description": "CRUD patch operation over person",
              "operationId": "zzz_patch_person",
              "parameters": [
                {
                  "$ref": "#/components/parameters/person"
                }
              ],
              "requestBody": {
                "$ref": "#/components/requestBodies/person"
              },
              "responses": {
                "default": {
                  "$ref": "#/components/responses/Error"
                },
                "200": {
                  "$ref": "#/components/responses/person"
                }
              }
            }
          },
          "/product": {
            "get": {
              "tags": [
                "product"
              ],
              "description": "CRUD get operation over product",
              "operationId": "zzz_get_product",
              "parameters": [
                {
                  "$ref": "#/components/parameters/product"
                }
              ],
              "responses": {
                "default": {
                  "$ref": "#/components/responses/Error"
                },
                "200": {
                  "$ref": "#/components/responses/productList"
                }
              }
            },
            "put": {
              "tags": [
                "product"
              ],
              "description": "CRUD put operation over product",
              "operationId": "zzz_put_product",
              "parameters": [
                {
                  "$ref": "#/components/parameters/product"
                }
              ],
              "requestBody": {
                "$ref": "#/components/requestBodies/product"
              },
              "responses": {
                "default": {
                  "$ref": "#/components/responses/Error"
                },
                "200": {
                  "$ref": "#/components/responses/product"
                }
              }
            },
            "post": {
              "tags": [
                "product"
              ],
              "description": "CRUD post operation over product",
              "operationId": "zzz_post_product",
              "requestBody": {
                "$ref": "#/components/requestBodies/product"
              },
              "responses": {
                "default": {
                  "$ref": "#/components/responses/Error"
                },
                "200": {
                  "$ref": "#/components/responses/product"
                }
              }
            },
            "delete": {
              "tags": [
                "product"
              ],
              "description": "CRUD delete operation over product",
              "operationId": "zzz_delete_product",
              "parameters": [
                {
                  "$ref": "#/components/parameters/product"
                }
              ],
              "responses": {
                "default": {
                  "$ref": "#/components/responses/Error"
                },
                "200": {
                  "$ref": "#/components/responses/product"
                }
              }
            },
            "patch": {
              "tags": [
                "product"
              ],
              "description": "CRUD patch operation over product",
              "operationId": "zzz_patch_product",
              "parameters": [
                {
                  "$ref": "#/components/parameters/product"
                }
              ],
              "requestBody": {
                "$ref": "#/components/requestBodies/product"
              },
              "responses": {
                "default": {
                  "$ref": "#/components/responses/Error"
                },
                "200": {
                  "$ref": "#/components/responses/product"
                }
              }
            }
          },
          "/request": {
            "get": {
              "tags": [
                "request"
              ],
              "description": "CRUD get operation over request",
              "operationId": "zzz_get_request",
              "parameters": [
                {
                  "$ref": "#/components/parameters/request"
                }
              ],
              "responses": {
                "default": {
                  "$ref": "#/components/responses/Error"
                },
                "200": {
                  "$ref": "#/components/responses/requestList"
                }
              }
            },
            "put": {
              "tags": [
                "request"
              ],
              "description": "CRUD put operation over request",
              "operationId": "zzz_put_request",
              "parameters": [
                {
                  "$ref": "#/components/parameters/request"
                }
              ],
              "requestBody": {
                "$ref": "#/components/requestBodies/request"
              },
              "responses": {
                "default": {
                  "$ref": "#/components/responses/Error"
                },
                "200": {
                  "$ref": "#/components/responses/request"
                }
              }
            },
            "post": {
              "tags": [
                "request"
              ],
              "description": "CRUD post operation over request",
              "operationId": "zzz_post_request",
              "requestBody": {
                "$ref": "#/components/requestBodies/request"
              },
              "responses": {
                "default": {
                  "$ref": "#/components/responses/Error"
                },
                "200": {
                  "$ref": "#/components/responses/request"
                }
              }
            },
            "delete": {
              "tags": [
                "request"
              ],
              "description": "CRUD delete operation over request",
              "operationId": "zzz_delete_request",
              "parameters": [
                {
                  "$ref": "#/components/parameters/request"
                }
              ],
              "responses": {
                "default": {
                  "$ref": "#/components/responses/Error"
                },
                "200": {
                  "$ref": "#/components/responses/request"
                }
              }
            },
            "patch": {
              "tags": [
                "request"
              ],
              "description": "CRUD patch operation over request",
              "operationId": "zzz_patch_request",
              "parameters": [
                {
                  "$ref": "#/components/parameters/request"
                }
              ],
              "requestBody": {
                "$ref": "#/components/requestBodies/request"
              },
              "responses": {
                "default": {
                  "$ref": "#/components/responses/Error"
                },
                "200": {
                  "$ref": "#/components/responses/request"
                }
              }
            }
          },
          "/request_freight": {
            "get": {
              "tags": [
                "requestFreight"
              ],
              "description": "CRUD get operation over requestFreight",
              "operationId": "zzz_get_requestFreight",
              "parameters": [
                {
                  "$ref": "#/components/parameters/requestFreight"
                }
              ],
              "responses": {
                "default": {
                  "$ref": "#/components/responses/Error"
                },
                "200": {
                  "$ref": "#/components/responses/requestFreightList"
                }
              }
            },
            "put": {
              "tags": [
                "requestFreight"
              ],
              "description": "CRUD put operation over requestFreight",
              "operationId": "zzz_put_requestFreight",
              "parameters": [
                {
                  "$ref": "#/components/parameters/requestFreight"
                }
              ],
              "requestBody": {
                "$ref": "#/components/requestBodies/requestFreight"
              },
              "responses": {
                "default": {
                  "$ref": "#/components/responses/Error"
                },
                "200": {
                  "$ref": "#/components/responses/requestFreight"
                }
              }
            },
            "post": {
              "tags": [
                "requestFreight"
              ],
              "description": "CRUD post operation over requestFreight",
              "operationId": "zzz_post_requestFreight",
              "requestBody": {
                "$ref": "#/components/requestBodies/requestFreight"
              },
              "responses": {
                "default": {
                  "$ref": "#/components/responses/Error"
                },
                "200": {
                  "$ref": "#/components/responses/requestFreight"
                }
              }
            },
            "delete": {
              "tags": [
                "requestFreight"
              ],
              "description": "CRUD delete operation over requestFreight",
              "operationId": "zzz_delete_requestFreight",
              "parameters": [
                {
                  "$ref": "#/components/parameters/requestFreight"
                }
              ],
              "responses": {
                "default": {
                  "$ref": "#/components/responses/Error"
                },
                "200": {
                  "$ref": "#/components/responses/requestFreight"
                }
              }
            },
            "patch": {
              "tags": [
                "requestFreight"
              ],
              "description": "CRUD patch operation over requestFreight",
              "operationId": "zzz_patch_requestFreight",
              "parameters": [
                {
                  "$ref": "#/components/parameters/requestFreight"
                }
              ],
              "requestBody": {
                "$ref": "#/components/requestBodies/requestFreight"
              },
              "responses": {
                "default": {
                  "$ref": "#/components/responses/Error"
                },
                "200": {
                  "$ref": "#/components/responses/requestFreight"
                }
              }
            }
          },
          "/request_nfe": {
            "get": {
              "tags": [
                "requestNfe"
              ],
              "description": "CRUD get operation over requestNfe",
              "operationId": "zzz_get_requestNfe",
              "parameters": [
                {
                  "$ref": "#/components/parameters/requestNfe"
                }
              ],
              "responses": {
                "default": {
                  "$ref": "#/components/responses/Error"
                },
                "200": {
                  "$ref": "#/components/responses/requestNfeList"
                }
              }
            },
            "put": {
              "tags": [
                "requestNfe"
              ],
              "description": "CRUD put operation over requestNfe",
              "operationId": "zzz_put_requestNfe",
              "parameters": [
                {
                  "$ref": "#/components/parameters/requestNfe"
                }
              ],
              "requestBody": {
                "$ref": "#/components/requestBodies/requestNfe"
              },
              "responses": {
                "default": {
                  "$ref": "#/components/responses/Error"
                },
                "200": {
                  "$ref": "#/components/responses/requestNfe"
                }
              }
            },
            "post": {
              "tags": [
                "requestNfe"
              ],
              "description": "CRUD post operation over requestNfe",
              "operationId": "zzz_post_requestNfe",
              "requestBody": {
                "$ref": "#/components/requestBodies/requestNfe"
              },
              "responses": {
                "default": {
                  "$ref": "#/components/responses/Error"
                },
                "200": {
                  "$ref": "#/components/responses/requestNfe"
                }
              }
            },
            "delete": {
              "tags": [
                "requestNfe"
              ],
              "description": "CRUD delete operation over requestNfe",
              "operationId": "zzz_delete_requestNfe",
              "parameters": [
                {
                  "$ref": "#/components/parameters/requestNfe"
                }
              ],
              "responses": {
                "default": {
                  "$ref": "#/components/responses/Error"
                },
                "200": {
                  "$ref": "#/components/responses/requestNfe"
                }
              }
            },
            "patch": {
              "tags": [
                "requestNfe"
              ],
              "description": "CRUD patch operation over requestNfe",
              "operationId": "zzz_patch_requestNfe",
              "parameters": [
                {
                  "$ref": "#/components/parameters/requestNfe"
                }
              ],
              "requestBody": {
                "$ref": "#/components/requestBodies/requestNfe"
              },
              "responses": {
                "default": {
                  "$ref": "#/components/responses/Error"
                },
                "200": {
                  "$ref": "#/components/responses/requestNfe"
                }
              }
            }
          },
          "/request_payment": {
            "get": {
              "tags": [
                "requestPayment"
              ],
              "description": "CRUD get operation over requestPayment",
              "operationId": "zzz_get_requestPayment",
              "parameters": [
                {
                  "$ref": "#/components/parameters/requestPayment"
                }
              ],
              "responses": {
                "default": {
                  "$ref": "#/components/responses/Error"
                },
                "200": {
                  "$ref": "#/components/responses/requestPaymentList"
                }
              }
            },
            "put": {
              "tags": [
                "requestPayment"
              ],
              "description": "CRUD put operation over requestPayment",
              "operationId": "zzz_put_requestPayment",
              "parameters": [
                {
                  "$ref": "#/components/parameters/requestPayment"
                }
              ],
              "requestBody": {
                "$ref": "#/components/requestBodies/requestPayment"
              },
              "responses": {
                "default": {
                  "$ref": "#/components/responses/Error"
                },
                "200": {
                  "$ref": "#/components/responses/requestPayment"
                }
              }
            },
            "post": {
              "tags": [
                "requestPayment"
              ],
              "description": "CRUD post operation over requestPayment",
              "operationId": "zzz_post_requestPayment",
              "requestBody": {
                "$ref": "#/components/requestBodies/requestPayment"
              },
              "responses": {
                "default": {
                  "$ref": "#/components/responses/Error"
                },
                "200": {
                  "$ref": "#/components/responses/requestPayment"
                }
              }
            },
            "delete": {
              "tags": [
                "requestPayment"
              ],
              "description": "CRUD delete operation over requestPayment",
              "operationId": "zzz_delete_requestPayment",
              "parameters": [
                {
                  "$ref": "#/components/parameters/requestPayment"
                }
              ],
              "responses": {
                "default": {
                  "$ref": "#/components/responses/Error"
                },
                "200": {
                  "$ref": "#/components/responses/requestPayment"
                }
              }
            },
            "patch": {
              "tags": [
                "requestPayment"
              ],
              "description": "CRUD patch operation over requestPayment",
              "operationId": "zzz_patch_requestPayment",
              "parameters": [
                {
                  "$ref": "#/components/parameters/requestPayment"
                }
              ],
              "requestBody": {
                "$ref": "#/components/requestBodies/requestPayment"
              },
              "responses": {
                "default": {
                  "$ref": "#/components/responses/Error"
                },
                "200": {
                  "$ref": "#/components/responses/requestPayment"
                }
              }
            }
          },
          "/request_product": {
            "get": {
              "tags": [
                "requestProduct"
              ],
              "description": "CRUD get operation over requestProduct",
              "operationId": "zzz_get_requestProduct",
              "parameters": [
                {
                  "$ref": "#/components/parameters/requestProduct"
                }
              ],
              "responses": {
                "default": {
                  "$ref": "#/components/responses/Error"
                },
                "200": {
                  "$ref": "#/components/responses/requestProductList"
                }
              }
            },
            "put": {
              "tags": [
                "requestProduct"
              ],
              "description": "CRUD put operation over requestProduct",
              "operationId": "zzz_put_requestProduct",
              "parameters": [
                {
                  "$ref": "#/components/parameters/requestProduct"
                }
              ],
              "requestBody": {
                "$ref": "#/components/requestBodies/requestProduct"
              },
              "responses": {
                "default": {
                  "$ref": "#/components/responses/Error"
                },
                "200": {
                  "$ref": "#/components/responses/requestProduct"
                }
              }
            },
            "post": {
              "tags": [
                "requestProduct"
              ],
              "description": "CRUD post operation over requestProduct",
              "operationId": "zzz_post_requestProduct",
              "requestBody": {
                "$ref": "#/components/requestBodies/requestProduct"
              },
              "responses": {
                "default": {
                  "$ref": "#/components/responses/Error"
                },
                "200": {
                  "$ref": "#/components/responses/requestProduct"
                }
              }
            },
            "delete": {
              "tags": [
                "requestProduct"
              ],
              "description": "CRUD delete operation over requestProduct",
              "operationId": "zzz_delete_requestProduct",
              "parameters": [
                {
                  "$ref": "#/components/parameters/requestProduct"
                }
              ],
              "responses": {
                "default": {
                  "$ref": "#/components/responses/Error"
                },
                "200": {
                  "$ref": "#/components/responses/requestProduct"
                }
              }
            },
            "patch": {
              "tags": [
                "requestProduct"
              ],
              "description": "CRUD patch operation over requestProduct",
              "operationId": "zzz_patch_requestProduct",
              "parameters": [
                {
                  "$ref": "#/components/parameters/requestProduct"
                }
              ],
              "requestBody": {
                "$ref": "#/components/requestBodies/requestProduct"
              },
              "responses": {
                "default": {
                  "$ref": "#/components/responses/Error"
                },
                "200": {
                  "$ref": "#/components/responses/requestProduct"
                }
              }
            }
          },
          "/request_service": {
            "get": {
              "tags": [
                "requestService"
              ],
              "description": "CRUD get operation over requestService",
              "operationId": "zzz_get_requestService",
              "parameters": [
                {
                  "$ref": "#/components/parameters/requestService"
                }
              ],
              "responses": {
                "default": {
                  "$ref": "#/components/responses/Error"
                },
                "200": {
                  "$ref": "#/components/responses/requestServiceList"
                }
              }
            },
            "put": {
              "tags": [
                "requestService"
              ],
              "description": "CRUD put operation over requestService",
              "operationId": "zzz_put_requestService",
              "parameters": [
                {
                  "$ref": "#/components/parameters/requestService"
                }
              ],
              "requestBody": {
                "$ref": "#/components/requestBodies/requestService"
              },
              "responses": {
                "default": {
                  "$ref": "#/components/responses/Error"
                },
                "200": {
                  "$ref": "#/components/responses/requestService"
                }
              }
            },
            "post": {
              "tags": [
                "requestService"
              ],
              "description": "CRUD post operation over requestService",
              "operationId": "zzz_post_requestService",
              "requestBody": {
                "$ref": "#/components/requestBodies/requestService"
              },
              "responses": {
                "default": {
                  "$ref": "#/components/responses/Error"
                },
                "200": {
                  "$ref": "#/components/responses/requestService"
                }
              }
            },
            "delete": {
              "tags": [
                "requestService"
              ],
              "description": "CRUD delete operation over requestService",
              "operationId": "zzz_delete_requestService",
              "parameters": [
                {
                  "$ref": "#/components/parameters/requestService"
                }
              ],
              "responses": {
                "default": {
                  "$ref": "#/components/responses/Error"
                },
                "200": {
                  "$ref": "#/components/responses/requestService"
                }
              }
            },
            "patch": {
              "tags": [
                "requestService"
              ],
              "description": "CRUD patch operation over requestService",
              "operationId": "zzz_patch_requestService",
              "parameters": [
                {
                  "$ref": "#/components/parameters/requestService"
                }
              ],
              "requestBody": {
                "$ref": "#/components/requestBodies/requestService"
              },
              "responses": {
                "default": {
                  "$ref": "#/components/responses/Error"
                },
                "200": {
                  "$ref": "#/components/responses/requestService"
                }
              }
            }
          },
          "/request_state": {
            "get": {
              "tags": [
                "requestState"
              ],
              "description": "CRUD get operation over requestState",
              "operationId": "zzz_get_requestState",
              "parameters": [
                {
                  "$ref": "#/components/parameters/requestState"
                }
              ],
              "responses": {
                "default": {
                  "$ref": "#/components/responses/Error"
                },
                "200": {
                  "$ref": "#/components/responses/requestStateList"
                }
              }
            },
            "put": {
              "tags": [
                "requestState"
              ],
              "description": "CRUD put operation over requestState",
              "operationId": "zzz_put_requestState",
              "parameters": [
                {
                  "$ref": "#/components/parameters/requestState"
                }
              ],
              "requestBody": {
                "$ref": "#/components/requestBodies/requestState"
              },
              "responses": {
                "default": {
                  "$ref": "#/components/responses/Error"
                },
                "200": {
                  "$ref": "#/components/responses/requestState"
                }
              }
            },
            "post": {
              "tags": [
                "requestState"
              ],
              "description": "CRUD post operation over requestState",
              "operationId": "zzz_post_requestState",
              "requestBody": {
                "$ref": "#/components/requestBodies/requestState"
              },
              "responses": {
                "default": {
                  "$ref": "#/components/responses/Error"
                },
                "200": {
                  "$ref": "#/components/responses/requestState"
                }
              }
            },
            "delete": {
              "tags": [
                "requestState"
              ],
              "description": "CRUD delete operation over requestState",
              "operationId": "zzz_delete_requestState",
              "parameters": [
                {
                  "$ref": "#/components/parameters/requestState"
                }
              ],
              "responses": {
                "default": {
                  "$ref": "#/components/responses/Error"
                },
                "200": {
                  "$ref": "#/components/responses/requestState"
                }
              }
            },
            "patch": {
              "tags": [
                "requestState"
              ],
              "description": "CRUD patch operation over requestState",
              "operationId": "zzz_patch_requestState",
              "parameters": [
                {
                  "$ref": "#/components/parameters/requestState"
                }
              ],
              "requestBody": {
                "$ref": "#/components/requestBodies/requestState"
              },
              "responses": {
                "default": {
                  "$ref": "#/components/responses/Error"
                },
                "200": {
                  "$ref": "#/components/responses/requestState"
                }
              }
            }
          },
          "/request_type": {
            "get": {
              "tags": [
                "requestType"
              ],
              "description": "CRUD get operation over requestType",
              "operationId": "zzz_get_requestType",
              "parameters": [
                {
                  "$ref": "#/components/parameters/requestType"
                }
              ],
              "responses": {
                "default": {
                  "$ref": "#/components/responses/Error"
                },
                "200": {
                  "$ref": "#/components/responses/requestTypeList"
                }
              }
            },
            "put": {
              "tags": [
                "requestType"
              ],
              "description": "CRUD put operation over requestType",
              "operationId": "zzz_put_requestType",
              "parameters": [
                {
                  "$ref": "#/components/parameters/requestType"
                }
              ],
              "requestBody": {
                "$ref": "#/components/requestBodies/requestType"
              },
              "responses": {
                "default": {
                  "$ref": "#/components/responses/Error"
                },
                "200": {
                  "$ref": "#/components/responses/requestType"
                }
              }
            },
            "post": {
              "tags": [
                "requestType"
              ],
              "description": "CRUD post operation over requestType",
              "operationId": "zzz_post_requestType",
              "requestBody": {
                "$ref": "#/components/requestBodies/requestType"
              },
              "responses": {
                "default": {
                  "$ref": "#/components/responses/Error"
                },
                "200": {
                  "$ref": "#/components/responses/requestType"
                }
              }
            },
            "delete": {
              "tags": [
                "requestType"
              ],
              "description": "CRUD delete operation over requestType",
              "operationId": "zzz_delete_requestType",
              "parameters": [
                {
                  "$ref": "#/components/parameters/requestType"
                }
              ],
              "responses": {
                "default": {
                  "$ref": "#/components/responses/Error"
                },
                "200": {
                  "$ref": "#/components/responses/requestType"
                }
              }
            },
            "patch": {
              "tags": [
                "requestType"
              ],
              "description": "CRUD patch operation over requestType",
              "operationId": "zzz_patch_requestType",
              "parameters": [
                {
                  "$ref": "#/components/parameters/requestType"
                }
              ],
              "requestBody": {
                "$ref": "#/components/requestBodies/requestType"
              },
              "responses": {
                "default": {
                  "$ref": "#/components/responses/Error"
                },
                "200": {
                  "$ref": "#/components/responses/requestType"
                }
              }
            }
          },
          "/rufs_group": {
            "get": {
              "tags": [
                "rufsGroup"
              ],
              "description": "CRUD get operation over rufsGroup",
              "operationId": "zzz_get_rufsGroup",
              "parameters": [
                {
                  "$ref": "#/components/parameters/rufsGroup"
                }
              ],
              "responses": {
                "default": {
                  "$ref": "#/components/responses/Error"
                },
                "200": {
                  "$ref": "#/components/responses/rufsGroupList"
                }
              },
              "security": [
                {
                  "jwt": []
                }
              ]
            },
            "put": {
              "tags": [
                "rufsGroup"
              ],
              "description": "CRUD put operation over rufsGroup",
              "operationId": "zzz_put_rufsGroup",
              "parameters": [
                {
                  "$ref": "#/components/parameters/rufsGroup"
                }
              ],
              "requestBody": {
                "$ref": "#/components/requestBodies/rufsGroup"
              },
              "responses": {
                "default": {
                  "$ref": "#/components/responses/Error"
                },
                "200": {
                  "$ref": "#/components/responses/rufsGroup"
                }
              },
              "security": [
                {
                  "jwt": []
                }
              ]
            },
            "post": {
              "tags": [
                "rufsGroup"
              ],
              "description": "CRUD post operation over rufsGroup",
              "operationId": "zzz_post_rufsGroup",
              "requestBody": {
                "$ref": "#/components/requestBodies/rufsGroup"
              },
              "responses": {
                "default": {
                  "$ref": "#/components/responses/Error"
                },
                "200": {
                  "$ref": "#/components/responses/rufsGroup"
                }
              },
              "security": [
                {
                  "jwt": []
                }
              ]
            },
            "delete": {
              "tags": [
                "rufsGroup"
              ],
              "description": "CRUD delete operation over rufsGroup",
              "operationId": "zzz_delete_rufsGroup",
              "parameters": [
                {
                  "$ref": "#/components/parameters/rufsGroup"
                }
              ],
              "responses": {
                "default": {
                  "$ref": "#/components/responses/Error"
                },
                "200": {
                  "$ref": "#/components/responses/rufsGroup"
                }
              },
              "security": [
                {
                  "jwt": []
                }
              ]
            },
            "patch": {
              "tags": [
                "rufsGroup"
              ],
              "description": "CRUD patch operation over rufsGroup",
              "operationId": "zzz_patch_rufsGroup",
              "parameters": [
                {
                  "$ref": "#/components/parameters/rufsGroup"
                }
              ],
              "requestBody": {
                "$ref": "#/components/requestBodies/rufsGroup"
              },
              "responses": {
                "default": {
                  "$ref": "#/components/responses/Error"
                },
                "200": {
                  "$ref": "#/components/responses/rufsGroup"
                }
              },
              "security": [
                {
                  "jwt": []
                }
              ]
            }
          },
          "/rufs_group_owner": {
            "get": {
              "tags": [
                "rufsGroupOwner"
              ],
              "description": "CRUD get operation over rufsGroupOwner",
              "operationId": "zzz_get_rufsGroupOwner",
              "parameters": [
                {
                  "$ref": "#/components/parameters/rufsGroupOwner"
                }
              ],
              "responses": {
                "default": {
                  "$ref": "#/components/responses/Error"
                },
                "200": {
                  "$ref": "#/components/responses/rufsGroupOwnerList"
                }
              },
              "security": [
                {
                  "jwt": []
                }
              ]
            },
            "put": {
              "tags": [
                "rufsGroupOwner"
              ],
              "description": "CRUD put operation over rufsGroupOwner",
              "operationId": "zzz_put_rufsGroupOwner",
              "parameters": [
                {
                  "$ref": "#/components/parameters/rufsGroupOwner"
                }
              ],
              "requestBody": {
                "$ref": "#/components/requestBodies/rufsGroupOwner"
              },
              "responses": {
                "default": {
                  "$ref": "#/components/responses/Error"
                },
                "200": {
                  "$ref": "#/components/responses/rufsGroupOwner"
                }
              },
              "security": [
                {
                  "jwt": []
                }
              ]
            },
            "post": {
              "tags": [
                "rufsGroupOwner"
              ],
              "description": "CRUD post operation over rufsGroupOwner",
              "operationId": "zzz_post_rufsGroupOwner",
              "requestBody": {
                "$ref": "#/components/requestBodies/rufsGroupOwner"
              },
              "responses": {
                "default": {
                  "$ref": "#/components/responses/Error"
                },
                "200": {
                  "$ref": "#/components/responses/rufsGroupOwner"
                }
              },
              "security": [
                {
                  "jwt": []
                }
              ]
            },
            "delete": {
              "tags": [
                "rufsGroupOwner"
              ],
              "description": "CRUD delete operation over rufsGroupOwner",
              "operationId": "zzz_delete_rufsGroupOwner",
              "parameters": [
                {
                  "$ref": "#/components/parameters/rufsGroupOwner"
                }
              ],
              "responses": {
                "default": {
                  "$ref": "#/components/responses/Error"
                },
                "200": {
                  "$ref": "#/components/responses/rufsGroupOwner"
                }
              },
              "security": [
                {
                  "jwt": []
                }
              ]
            },
            "patch": {
              "tags": [
                "rufsGroupOwner"
              ],
              "description": "CRUD patch operation over rufsGroupOwner",
              "operationId": "zzz_patch_rufsGroupOwner",
              "parameters": [
                {
                  "$ref": "#/components/parameters/rufsGroupOwner"
                }
              ],
              "requestBody": {
                "$ref": "#/components/requestBodies/rufsGroupOwner"
              },
              "responses": {
                "default": {
                  "$ref": "#/components/responses/Error"
                },
                "200": {
                  "$ref": "#/components/responses/rufsGroupOwner"
                }
              },
              "security": [
                {
                  "jwt": []
                }
              ]
            }
          },
          "/rufs_group_user": {
            "get": {
              "tags": [
                "rufsGroupUser"
              ],
              "description": "CRUD get operation over rufsGroupUser",
              "operationId": "zzz_get_rufsGroupUser",
              "parameters": [
                {
                  "$ref": "#/components/parameters/rufsGroupUser"
                }
              ],
              "responses": {
                "default": {
                  "$ref": "#/components/responses/Error"
                },
                "200": {
                  "$ref": "#/components/responses/rufsGroupUserList"
                }
              },
              "security": [
                {
                  "jwt": []
                }
              ]
            },
            "put": {
              "tags": [
                "rufsGroupUser"
              ],
              "description": "CRUD put operation over rufsGroupUser",
              "operationId": "zzz_put_rufsGroupUser",
              "parameters": [
                {
                  "$ref": "#/components/parameters/rufsGroupUser"
                }
              ],
              "requestBody": {
                "$ref": "#/components/requestBodies/rufsGroupUser"
              },
              "responses": {
                "default": {
                  "$ref": "#/components/responses/Error"
                },
                "200": {
                  "$ref": "#/components/responses/rufsGroupUser"
                }
              },
              "security": [
                {
                  "jwt": []
                }
              ]
            },
            "post": {
              "tags": [
                "rufsGroupUser"
              ],
              "description": "CRUD post operation over rufsGroupUser",
              "operationId": "zzz_post_rufsGroupUser",
              "requestBody": {
                "$ref": "#/components/requestBodies/rufsGroupUser"
              },
              "responses": {
                "default": {
                  "$ref": "#/components/responses/Error"
                },
                "200": {
                  "$ref": "#/components/responses/rufsGroupUser"
                }
              },
              "security": [
                {
                  "jwt": []
                }
              ]
            },
            "delete": {
              "tags": [
                "rufsGroupUser"
              ],
              "description": "CRUD delete operation over rufsGroupUser",
              "operationId": "zzz_delete_rufsGroupUser",
              "parameters": [
                {
                  "$ref": "#/components/parameters/rufsGroupUser"
                }
              ],
              "responses": {
                "default": {
                  "$ref": "#/components/responses/Error"
                },
                "200": {
                  "$ref": "#/components/responses/rufsGroupUser"
                }
              },
              "security": [
                {
                  "jwt": []
                }
              ]
            },
            "patch": {
              "tags": [
                "rufsGroupUser"
              ],
              "description": "CRUD patch operation over rufsGroupUser",
              "operationId": "zzz_patch_rufsGroupUser",
              "parameters": [
                {
                  "$ref": "#/components/parameters/rufsGroupUser"
                }
              ],
              "requestBody": {
                "$ref": "#/components/requestBodies/rufsGroupUser"
              },
              "responses": {
                "default": {
                  "$ref": "#/components/responses/Error"
                },
                "200": {
                  "$ref": "#/components/responses/rufsGroupUser"
                }
              },
              "security": [
                {
                  "jwt": []
                }
              ]
            }
          },
          "/rufs_user": {
            "get": {
              "tags": [
                "rufsUser"
              ],
              "description": "CRUD get operation over rufsUser",
              "operationId": "zzz_get_rufsUser",
              "parameters": [
                {
                  "$ref": "#/components/parameters/rufsUser"
                }
              ],
              "responses": {
                "default": {
                  "$ref": "#/components/responses/Error"
                },
                "200": {
                  "$ref": "#/components/responses/rufsUserList"
                }
              },
              "security": [
                {
                  "jwt": []
                }
              ]
            },
            "put": {
              "tags": [
                "rufsUser"
              ],
              "description": "CRUD put operation over rufsUser",
              "operationId": "zzz_put_rufsUser",
              "parameters": [
                {
                  "$ref": "#/components/parameters/rufsUser"
                }
              ],
              "requestBody": {
                "$ref": "#/components/requestBodies/rufsUser"
              },
              "responses": {
                "default": {
                  "$ref": "#/components/responses/Error"
                },
                "200": {
                  "$ref": "#/components/responses/rufsUser"
                }
              },
              "security": [
                {
                  "jwt": []
                }
              ]
            },
            "post": {
              "tags": [
                "rufsUser"
              ],
              "description": "CRUD post operation over rufsUser",
              "operationId": "zzz_post_rufsUser",
              "requestBody": {
                "$ref": "#/components/requestBodies/rufsUser"
              },
              "responses": {
                "default": {
                  "$ref": "#/components/responses/Error"
                },
                "200": {
                  "$ref": "#/components/responses/rufsUser"
                }
              },
              "security": [
                {
                  "jwt": []
                }
              ]
            },
            "delete": {
              "tags": [
                "rufsUser"
              ],
              "description": "CRUD delete operation over rufsUser",
              "operationId": "zzz_delete_rufsUser",
              "parameters": [
                {
                  "$ref": "#/components/parameters/rufsUser"
                }
              ],
              "responses": {
                "default": {
                  "$ref": "#/components/responses/Error"
                },
                "200": {
                  "$ref": "#/components/responses/rufsUser"
                }
              },
              "security": [
                {
                  "jwt": []
                }
              ]
            },
            "patch": {
              "tags": [
                "rufsUser"
              ],
              "description": "CRUD patch operation over rufsUser",
              "operationId": "zzz_patch_rufsUser",
              "parameters": [
                {
                  "$ref": "#/components/parameters/rufsUser"
                }
              ],
              "requestBody": {
                "$ref": "#/components/requestBodies/rufsUser"
              },
              "responses": {
                "default": {
                  "$ref": "#/components/responses/Error"
                },
                "200": {
                  "$ref": "#/components/responses/rufsUser"
                }
              },
              "security": [
                {
                  "jwt": []
                }
              ]
            }
          },
          "/service": {
            "get": {
              "tags": [
                "service"
              ],
              "description": "CRUD get operation over service",
              "operationId": "zzz_get_service",
              "parameters": [
                {
                  "$ref": "#/components/parameters/service"
                }
              ],
              "responses": {
                "default": {
                  "$ref": "#/components/responses/Error"
                },
                "200": {
                  "$ref": "#/components/responses/serviceList"
                }
              }
            },
            "put": {
              "tags": [
                "service"
              ],
              "description": "CRUD put operation over service",
              "operationId": "zzz_put_service",
              "parameters": [
                {
                  "$ref": "#/components/parameters/service"
                }
              ],
              "requestBody": {
                "$ref": "#/components/requestBodies/service"
              },
              "responses": {
                "default": {
                  "$ref": "#/components/responses/Error"
                },
                "200": {
                  "$ref": "#/components/responses/service"
                }
              }
            },
            "post": {
              "tags": [
                "service"
              ],
              "description": "CRUD post operation over service",
              "operationId": "zzz_post_service",
              "requestBody": {
                "$ref": "#/components/requestBodies/service"
              },
              "responses": {
                "default": {
                  "$ref": "#/components/responses/Error"
                },
                "200": {
                  "$ref": "#/components/responses/service"
                }
              }
            },
            "delete": {
              "tags": [
                "service"
              ],
              "description": "CRUD delete operation over service",
              "operationId": "zzz_delete_service",
              "parameters": [
                {
                  "$ref": "#/components/parameters/service"
                }
              ],
              "responses": {
                "default": {
                  "$ref": "#/components/responses/Error"
                },
                "200": {
                  "$ref": "#/components/responses/service"
                }
              }
            },
            "patch": {
              "tags": [
                "service"
              ],
              "description": "CRUD patch operation over service",
              "operationId": "zzz_patch_service",
              "parameters": [
                {
                  "$ref": "#/components/parameters/service"
                }
              ],
              "requestBody": {
                "$ref": "#/components/requestBodies/service"
              },
              "responses": {
                "default": {
                  "$ref": "#/components/responses/Error"
                },
                "200": {
                  "$ref": "#/components/responses/service"
                }
              }
            }
          },
          "/stock": {
            "get": {
              "tags": [
                "stock"
              ],
              "description": "CRUD get operation over stock",
              "operationId": "zzz_get_stock",
              "parameters": [
                {
                  "$ref": "#/components/parameters/stock"
                }
              ],
              "responses": {
                "default": {
                  "$ref": "#/components/responses/Error"
                },
                "200": {
                  "$ref": "#/components/responses/stockList"
                }
              }
            },
            "put": {
              "tags": [
                "stock"
              ],
              "description": "CRUD put operation over stock",
              "operationId": "zzz_put_stock",
              "parameters": [
                {
                  "$ref": "#/components/parameters/stock"
                }
              ],
              "requestBody": {
                "$ref": "#/components/requestBodies/stock"
              },
              "responses": {
                "default": {
                  "$ref": "#/components/responses/Error"
                },
                "200": {
                  "$ref": "#/components/responses/stock"
                }
              }
            },
            "post": {
              "tags": [
                "stock"
              ],
              "description": "CRUD post operation over stock",
              "operationId": "zzz_post_stock",
              "requestBody": {
                "$ref": "#/components/requestBodies/stock"
              },
              "responses": {
                "default": {
                  "$ref": "#/components/responses/Error"
                },
                "200": {
                  "$ref": "#/components/responses/stock"
                }
              }
            },
            "delete": {
              "tags": [
                "stock"
              ],
              "description": "CRUD delete operation over stock",
              "operationId": "zzz_delete_stock",
              "parameters": [
                {
                  "$ref": "#/components/parameters/stock"
                }
              ],
              "responses": {
                "default": {
                  "$ref": "#/components/responses/Error"
                },
                "200": {
                  "$ref": "#/components/responses/stock"
                }
              }
            },
            "patch": {
              "tags": [
                "stock"
              ],
              "description": "CRUD patch operation over stock",
              "operationId": "zzz_patch_stock",
              "parameters": [
                {
                  "$ref": "#/components/parameters/stock"
                }
              ],
              "requestBody": {
                "$ref": "#/components/requestBodies/stock"
              },
              "responses": {
                "default": {
                  "$ref": "#/components/responses/Error"
                },
                "200": {
                  "$ref": "#/components/responses/stock"
                }
              }
            }
          },
          "/stock_action": {
            "get": {
              "tags": [
                "stockAction"
              ],
              "description": "CRUD get operation over stockAction",
              "operationId": "zzz_get_stockAction",
              "parameters": [
                {
                  "$ref": "#/components/parameters/stockAction"
                }
              ],
              "responses": {
                "default": {
                  "$ref": "#/components/responses/Error"
                },
                "200": {
                  "$ref": "#/components/responses/stockActionList"
                }
              }
            },
            "put": {
              "tags": [
                "stockAction"
              ],
              "description": "CRUD put operation over stockAction",
              "operationId": "zzz_put_stockAction",
              "parameters": [
                {
                  "$ref": "#/components/parameters/stockAction"
                }
              ],
              "requestBody": {
                "$ref": "#/components/requestBodies/stockAction"
              },
              "responses": {
                "default": {
                  "$ref": "#/components/responses/Error"
                },
                "200": {
                  "$ref": "#/components/responses/stockAction"
                }
              }
            },
            "post": {
              "tags": [
                "stockAction"
              ],
              "description": "CRUD post operation over stockAction",
              "operationId": "zzz_post_stockAction",
              "requestBody": {
                "$ref": "#/components/requestBodies/stockAction"
              },
              "responses": {
                "default": {
                  "$ref": "#/components/responses/Error"
                },
                "200": {
                  "$ref": "#/components/responses/stockAction"
                }
              }
            },
            "delete": {
              "tags": [
                "stockAction"
              ],
              "description": "CRUD delete operation over stockAction",
              "operationId": "zzz_delete_stockAction",
              "parameters": [
                {
                  "$ref": "#/components/parameters/stockAction"
                }
              ],
              "responses": {
                "default": {
                  "$ref": "#/components/responses/Error"
                },
                "200": {
                  "$ref": "#/components/responses/stockAction"
                }
              }
            },
            "patch": {
              "tags": [
                "stockAction"
              ],
              "description": "CRUD patch operation over stockAction",
              "operationId": "zzz_patch_stockAction",
              "parameters": [
                {
                  "$ref": "#/components/parameters/stockAction"
                }
              ],
              "requestBody": {
                "$ref": "#/components/requestBodies/stockAction"
              },
              "responses": {
                "default": {
                  "$ref": "#/components/responses/Error"
                },
                "200": {
                  "$ref": "#/components/responses/stockAction"
                }
              }
            }
          }
        },
        "components": {
          "securitySchemes": {
            "jwt": {
              "type": "http",
              "scheme": "bearer",
              "bearerFormat": "JWT"
            },
            "apiKey": {
              "type": "apiKey",
              "in": "header",
              "name": "X-API-KEY"
            },
            "basic": {
              "type": "http",
              "scheme": "basic"
            }
          },
          "responses": {
            "Error": {
              "description": "Error response",
              "content": {
                "application/json": {
                  "schema": {
                    "type": "object",
                    "properties": {
                      "code": {
                        "type": "integer"
                      },
                      "description": {
                        "type": "string"
                      }
                    },
                    "required": [
                      "code",
                      "description"
                    ]
                  }
                }
              }
            },
            "login": {
              "description": "response",
              "content": {
                "application/json": {
                  "schema": {
                    "$ref": "#/components/schemas/login"
                  }
                }
              }
            },
            "loginList": {
              "description": "response list",
              "content": {
                "application/json": {
                  "schema": {
                    "type": "array",
                    "items": {
                      "$ref": "#/components/schemas/login"
                    }
                  }
                }
              }
            },
            "account": {
              "description": "response",
              "content": {
                "application/json": {
                  "schema": {
                    "$ref": "#/components/schemas/account"
                  }
                }
              }
            },
            "accountList": {
              "description": "response list",
              "content": {
                "application/json": {
                  "schema": {
                    "type": "array",
                    "items": {
                      "$ref": "#/components/schemas/account"
                    }
                  }
                }
              }
            },
            "bacenCountry": {
              "description": "response",
              "content": {
                "application/json": {
                  "schema": {
                    "$ref": "#/components/schemas/bacenCountry"
                  }
                }
              }
            },
            "bacenCountryList": {
              "description": "response list",
              "content": {
                "application/json": {
                  "schema": {
                    "type": "array",
                    "items": {
                      "$ref": "#/components/schemas/bacenCountry"
                    }
                  }
                }
              }
            },
            "barcode": {
              "description": "response",
              "content": {
                "application/json": {
                  "schema": {
                    "$ref": "#/components/schemas/barcode"
                  }
                }
              }
            },
            "barcodeList": {
              "description": "response list",
              "content": {
                "application/json": {
                  "schema": {
                    "type": "array",
                    "items": {
                      "$ref": "#/components/schemas/barcode"
                    }
                  }
                }
              }
            },
            "camexNcm": {
              "description": "response",
              "content": {
                "application/json": {
                  "schema": {
                    "$ref": "#/components/schemas/camexNcm"
                  }
                }
              }
            },
            "camexNcmList": {
              "description": "response list",
              "content": {
                "application/json": {
                  "schema": {
                    "type": "array",
                    "items": {
                      "$ref": "#/components/schemas/camexNcm"
                    }
                  }
                }
              }
            },
            "confazCest": {
              "description": "response",
              "content": {
                "application/json": {
                  "schema": {
                    "$ref": "#/components/schemas/confazCest"
                  }
                }
              }
            },
            "confazCestList": {
              "description": "response list",
              "content": {
                "application/json": {
                  "schema": {
                    "type": "array",
                    "items": {
                      "$ref": "#/components/schemas/confazCest"
                    }
                  }
                }
              }
            },
            "employed": {
              "description": "response",
              "content": {
                "application/json": {
                  "schema": {
                    "$ref": "#/components/schemas/employed"
                  }
                }
              }
            },
            "employedList": {
              "description": "response list",
              "content": {
                "application/json": {
                  "schema": {
                    "type": "array",
                    "items": {
                      "$ref": "#/components/schemas/employed"
                    }
                  }
                }
              }
            },
            "ibgeCity": {
              "description": "response",
              "content": {
                "application/json": {
                  "schema": {
                    "$ref": "#/components/schemas/ibgeCity"
                  }
                }
              }
            },
            "ibgeCityList": {
              "description": "response list",
              "content": {
                "application/json": {
                  "schema": {
                    "type": "array",
                    "items": {
                      "$ref": "#/components/schemas/ibgeCity"
                    }
                  }
                }
              }
            },
            "ibgeCnae": {
              "description": "response",
              "content": {
                "application/json": {
                  "schema": {
                    "$ref": "#/components/schemas/ibgeCnae"
                  }
                }
              }
            },
            "ibgeCnaeList": {
              "description": "response list",
              "content": {
                "application/json": {
                  "schema": {
                    "type": "array",
                    "items": {
                      "$ref": "#/components/schemas/ibgeCnae"
                    }
                  }
                }
              }
            },
            "ibgeUf": {
              "description": "response",
              "content": {
                "application/json": {
                  "schema": {
                    "$ref": "#/components/schemas/ibgeUf"
                  }
                }
              }
            },
            "ibgeUfList": {
              "description": "response list",
              "content": {
                "application/json": {
                  "schema": {
                    "type": "array",
                    "items": {
                      "$ref": "#/components/schemas/ibgeUf"
                    }
                  }
                }
              }
            },
            "nfeCfop": {
              "description": "response",
              "content": {
                "application/json": {
                  "schema": {
                    "$ref": "#/components/schemas/nfeCfop"
                  }
                }
              }
            },
            "nfeCfopList": {
              "description": "response list",
              "content": {
                "application/json": {
                  "schema": {
                    "type": "array",
                    "items": {
                      "$ref": "#/components/schemas/nfeCfop"
                    }
                  }
                }
              }
            },
            "nfeStCofins": {
              "description": "response",
              "content": {
                "application/json": {
                  "schema": {
                    "$ref": "#/components/schemas/nfeStCofins"
                  }
                }
              }
            },
            "nfeStCofinsList": {
              "description": "response list",
              "content": {
                "application/json": {
                  "schema": {
                    "type": "array",
                    "items": {
                      "$ref": "#/components/schemas/nfeStCofins"
                    }
                  }
                }
              }
            },
            "nfeStCsosn": {
              "description": "response",
              "content": {
                "application/json": {
                  "schema": {
                    "$ref": "#/components/schemas/nfeStCsosn"
                  }
                }
              }
            },
            "nfeStCsosnList": {
              "description": "response list",
              "content": {
                "application/json": {
                  "schema": {
                    "type": "array",
                    "items": {
                      "$ref": "#/components/schemas/nfeStCsosn"
                    }
                  }
                }
              }
            },
            "nfeStIcms": {
              "description": "response",
              "content": {
                "application/json": {
                  "schema": {
                    "$ref": "#/components/schemas/nfeStIcms"
                  }
                }
              }
            },
            "nfeStIcmsList": {
              "description": "response list",
              "content": {
                "application/json": {
                  "schema": {
                    "type": "array",
                    "items": {
                      "$ref": "#/components/schemas/nfeStIcms"
                    }
                  }
                }
              }
            },
            "nfeStIcmsDesoneracao": {
              "description": "response",
              "content": {
                "application/json": {
                  "schema": {
                    "$ref": "#/components/schemas/nfeStIcmsDesoneracao"
                  }
                }
              }
            },
            "nfeStIcmsDesoneracaoList": {
              "description": "response list",
              "content": {
                "application/json": {
                  "schema": {
                    "type": "array",
                    "items": {
                      "$ref": "#/components/schemas/nfeStIcmsDesoneracao"
                    }
                  }
                }
              }
            },
            "nfeStIcmsModalidadeBc": {
              "description": "response",
              "content": {
                "application/json": {
                  "schema": {
                    "$ref": "#/components/schemas/nfeStIcmsModalidadeBc"
                  }
                }
              }
            },
            "nfeStIcmsModalidadeBcList": {
              "description": "response list",
              "content": {
                "application/json": {
                  "schema": {
                    "type": "array",
                    "items": {
                      "$ref": "#/components/schemas/nfeStIcmsModalidadeBc"
                    }
                  }
                }
              }
            },
            "nfeStIcmsModalidadeSt": {
              "description": "response",
              "content": {
                "application/json": {
                  "schema": {
                    "$ref": "#/components/schemas/nfeStIcmsModalidadeSt"
                  }
                }
              }
            },
            "nfeStIcmsModalidadeStList": {
              "description": "response list",
              "content": {
                "application/json": {
                  "schema": {
                    "type": "array",
                    "items": {
                      "$ref": "#/components/schemas/nfeStIcmsModalidadeSt"
                    }
                  }
                }
              }
            },
            "nfeStIcmsOrigem": {
              "description": "response",
              "content": {
                "application/json": {
                  "schema": {
                    "$ref": "#/components/schemas/nfeStIcmsOrigem"
                  }
                }
              }
            },
            "nfeStIcmsOrigemList": {
              "description": "response list",
              "content": {
                "application/json": {
                  "schema": {
                    "type": "array",
                    "items": {
                      "$ref": "#/components/schemas/nfeStIcmsOrigem"
                    }
                  }
                }
              }
            },
            "nfeStIpi": {
              "description": "response",
              "content": {
                "application/json": {
                  "schema": {
                    "$ref": "#/components/schemas/nfeStIpi"
                  }
                }
              }
            },
            "nfeStIpiList": {
              "description": "response list",
              "content": {
                "application/json": {
                  "schema": {
                    "type": "array",
                    "items": {
                      "$ref": "#/components/schemas/nfeStIpi"
                    }
                  }
                }
              }
            },
            "nfeStIpiEnquadramento": {
              "description": "response",
              "content": {
                "application/json": {
                  "schema": {
                    "$ref": "#/components/schemas/nfeStIpiEnquadramento"
                  }
                }
              }
            },
            "nfeStIpiEnquadramentoList": {
              "description": "response list",
              "content": {
                "application/json": {
                  "schema": {
                    "type": "array",
                    "items": {
                      "$ref": "#/components/schemas/nfeStIpiEnquadramento"
                    }
                  }
                }
              }
            },
            "nfeStIpiOperacao": {
              "description": "response",
              "content": {
                "application/json": {
                  "schema": {
                    "$ref": "#/components/schemas/nfeStIpiOperacao"
                  }
                }
              }
            },
            "nfeStIpiOperacaoList": {
              "description": "response list",
              "content": {
                "application/json": {
                  "schema": {
                    "type": "array",
                    "items": {
                      "$ref": "#/components/schemas/nfeStIpiOperacao"
                    }
                  }
                }
              }
            },
            "nfeStPis": {
              "description": "response",
              "content": {
                "application/json": {
                  "schema": {
                    "$ref": "#/components/schemas/nfeStPis"
                  }
                }
              }
            },
            "nfeStPisList": {
              "description": "response list",
              "content": {
                "application/json": {
                  "schema": {
                    "type": "array",
                    "items": {
                      "$ref": "#/components/schemas/nfeStPis"
                    }
                  }
                }
              }
            },
            "nfeTaxGroup": {
              "description": "response",
              "content": {
                "application/json": {
                  "schema": {
                    "$ref": "#/components/schemas/nfeTaxGroup"
                  }
                }
              }
            },
            "nfeTaxGroupList": {
              "description": "response list",
              "content": {
                "application/json": {
                  "schema": {
                    "type": "array",
                    "items": {
                      "$ref": "#/components/schemas/nfeTaxGroup"
                    }
                  }
                }
              }
            },
            "nfseCodService": {
              "description": "response",
              "content": {
                "application/json": {
                  "schema": {
                    "$ref": "#/components/schemas/nfseCodService"
                  }
                }
              }
            },
            "nfseCodServiceList": {
              "description": "response list",
              "content": {
                "application/json": {
                  "schema": {
                    "type": "array",
                    "items": {
                      "$ref": "#/components/schemas/nfseCodService"
                    }
                  }
                }
              }
            },
            "paymentType": {
              "description": "response",
              "content": {
                "application/json": {
                  "schema": {
                    "$ref": "#/components/schemas/paymentType"
                  }
                }
              }
            },
            "paymentTypeList": {
              "description": "response list",
              "content": {
                "application/json": {
                  "schema": {
                    "type": "array",
                    "items": {
                      "$ref": "#/components/schemas/paymentType"
                    }
                  }
                }
              }
            },
            "person": {
              "description": "response",
              "content": {
                "application/json": {
                  "schema": {
                    "$ref": "#/components/schemas/person"
                  }
                }
              }
            },
            "personList": {
              "description": "response list",
              "content": {
                "application/json": {
                  "schema": {
                    "type": "array",
                    "items": {
                      "$ref": "#/components/schemas/person"
                    }
                  }
                }
              }
            },
            "product": {
              "description": "response",
              "content": {
                "application/json": {
                  "schema": {
                    "$ref": "#/components/schemas/product"
                  }
                }
              }
            },
            "productList": {
              "description": "response list",
              "content": {
                "application/json": {
                  "schema": {
                    "type": "array",
                    "items": {
                      "$ref": "#/components/schemas/product"
                    }
                  }
                }
              }
            },
            "request": {
              "description": "response",
              "content": {
                "application/json": {
                  "schema": {
                    "$ref": "#/components/schemas/request"
                  }
                }
              }
            },
            "requestList": {
              "description": "response list",
              "content": {
                "application/json": {
                  "schema": {
                    "type": "array",
                    "items": {
                      "$ref": "#/components/schemas/request"
                    }
                  }
                }
              }
            },
            "requestFreight": {
              "description": "response",
              "content": {
                "application/json": {
                  "schema": {
                    "$ref": "#/components/schemas/requestFreight"
                  }
                }
              }
            },
            "requestFreightList": {
              "description": "response list",
              "content": {
                "application/json": {
                  "schema": {
                    "type": "array",
                    "items": {
                      "$ref": "#/components/schemas/requestFreight"
                    }
                  }
                }
              }
            },
            "requestNfe": {
              "description": "response",
              "content": {
                "application/json": {
                  "schema": {
                    "$ref": "#/components/schemas/requestNfe"
                  }
                }
              }
            },
            "requestNfeList": {
              "description": "response list",
              "content": {
                "application/json": {
                  "schema": {
                    "type": "array",
                    "items": {
                      "$ref": "#/components/schemas/requestNfe"
                    }
                  }
                }
              }
            },
            "requestPayment": {
              "description": "response",
              "content": {
                "application/json": {
                  "schema": {
                    "$ref": "#/components/schemas/requestPayment"
                  }
                }
              }
            },
            "requestPaymentList": {
              "description": "response list",
              "content": {
                "application/json": {
                  "schema": {
                    "type": "array",
                    "items": {
                      "$ref": "#/components/schemas/requestPayment"
                    }
                  }
                }
              }
            },
            "requestProduct": {
              "description": "response",
              "content": {
                "application/json": {
                  "schema": {
                    "$ref": "#/components/schemas/requestProduct"
                  }
                }
              }
            },
            "requestProductList": {
              "description": "response list",
              "content": {
                "application/json": {
                  "schema": {
                    "type": "array",
                    "items": {
                      "$ref": "#/components/schemas/requestProduct"
                    }
                  }
                }
              }
            },
            "requestService": {
              "description": "response",
              "content": {
                "application/json": {
                  "schema": {
                    "$ref": "#/components/schemas/requestService"
                  }
                }
              }
            },
            "requestServiceList": {
              "description": "response list",
              "content": {
                "application/json": {
                  "schema": {
                    "type": "array",
                    "items": {
                      "$ref": "#/components/schemas/requestService"
                    }
                  }
                }
              }
            },
            "requestState": {
              "description": "response",
              "content": {
                "application/json": {
                  "schema": {
                    "$ref": "#/components/schemas/requestState"
                  }
                }
              }
            },
            "requestStateList": {
              "description": "response list",
              "content": {
                "application/json": {
                  "schema": {
                    "type": "array",
                    "items": {
                      "$ref": "#/components/schemas/requestState"
                    }
                  }
                }
              }
            },
            "requestType": {
              "description": "response",
              "content": {
                "application/json": {
                  "schema": {
                    "$ref": "#/components/schemas/requestType"
                  }
                }
              }
            },
            "requestTypeList": {
              "description": "response list",
              "content": {
                "application/json": {
                  "schema": {
                    "type": "array",
                    "items": {
                      "$ref": "#/components/schemas/requestType"
                    }
                  }
                }
              }
            },
            "rufsGroup": {
              "description": "response",
              "content": {
                "application/json": {
                  "schema": {
                    "$ref": "#/components/schemas/rufsGroup"
                  }
                }
              }
            },
            "rufsGroupList": {
              "description": "response list",
              "content": {
                "application/json": {
                  "schema": {
                    "type": "array",
                    "items": {
                      "$ref": "#/components/schemas/rufsGroup"
                    }
                  }
                }
              }
            },
            "rufsGroupOwner": {
              "description": "response",
              "content": {
                "application/json": {
                  "schema": {
                    "$ref": "#/components/schemas/rufsGroupOwner"
                  }
                }
              }
            },
            "rufsGroupOwnerList": {
              "description": "response list",
              "content": {
                "application/json": {
                  "schema": {
                    "type": "array",
                    "items": {
                      "$ref": "#/components/schemas/rufsGroupOwner"
                    }
                  }
                }
              }
            },
            "rufsGroupUser": {
              "description": "response",
              "content": {
                "application/json": {
                  "schema": {
                    "$ref": "#/components/schemas/rufsGroupUser"
                  }
                }
              }
            },
            "rufsGroupUserList": {
              "description": "response list",
              "content": {
                "application/json": {
                  "schema": {
                    "type": "array",
                    "items": {
                      "$ref": "#/components/schemas/rufsGroupUser"
                    }
                  }
                }
              }
            },
            "rufsUser": {
              "description": "response",
              "content": {
                "application/json": {
                  "schema": {
                    "$ref": "#/components/schemas/rufsUser"
                  }
                }
              }
            },
            "rufsUserList": {
              "description": "response list",
              "content": {
                "application/json": {
                  "schema": {
                    "type": "array",
                    "items": {
                      "$ref": "#/components/schemas/rufsUser"
                    }
                  }
                }
              }
            },
            "service": {
              "description": "response",
              "content": {
                "application/json": {
                  "schema": {
                    "$ref": "#/components/schemas/service"
                  }
                }
              }
            },
            "serviceList": {
              "description": "response list",
              "content": {
                "application/json": {
                  "schema": {
                    "type": "array",
                    "items": {
                      "$ref": "#/components/schemas/service"
                    }
                  }
                }
              }
            },
            "stock": {
              "description": "response",
              "content": {
                "application/json": {
                  "schema": {
                    "$ref": "#/components/schemas/stock"
                  }
                }
              }
            },
            "stockList": {
              "description": "response list",
              "content": {
                "application/json": {
                  "schema": {
                    "type": "array",
                    "items": {
                      "$ref": "#/components/schemas/stock"
                    }
                  }
                }
              }
            },
            "stockAction": {
              "description": "response",
              "content": {
                "application/json": {
                  "schema": {
                    "$ref": "#/components/schemas/stockAction"
                  }
                }
              }
            },
            "stockActionList": {
              "description": "response list",
              "content": {
                "application/json": {
                  "schema": {
                    "type": "array",
                    "items": {
                      "$ref": "#/components/schemas/stockAction"
                    }
                  }
                }
              }
            }
          },
          "parameters": {
            "account": {
              "in": "query",
              "name": "primaryKey",
              "required": true,
              "schema": {
                "type": "object",
                "properties": {
                  "rufsGroupOwner": {
                    "x-updatable": true,
                    "x-essential": true,
                    "x-$ref": "#/components/schemas/rufsGroupOwner",
                    "type": "integer"
                  },
                  "id": {
                    "x-updatable": true,
                    "x-identityGeneration": "BY DEFAULT",
                    "x-essential": true,
                    "type": "integer"
                  }
                },
                "required": [
                  "rufsGroupOwner",
                  "id"
                ]
              },
              "style": "form"
            },
            "bacenCountry": {
              "in": "query",
              "name": "primaryKey",
              "required": true,
              "schema": {
                "type": "object",
                "properties": {
                  "id": {
                    "default": 1058,
                    "x-updatable": true,
                    "x-essential": true,
                    "type": "integer"
                  }
                },
                "required": [
                  "id"
                ]
              },
              "style": "form"
            },
            "barcode": {
              "in": "query",
              "name": "primaryKey",
              "required": true,
              "schema": {
                "type": "object",
                "properties": {
                  "number": {
                    "x-updatable": true,
                    "x-essential": true,
                    "type": "string",
                    "maxLength": 14
                  }
                },
                "required": [
                  "number"
                ]
              },
              "style": "form"
            },
            "camexNcm": {
              "in": "query",
              "name": "primaryKey",
              "required": true,
              "schema": {
                "type": "object",
                "properties": {
                  "id": {
                    "x-updatable": true,
                    "x-essential": true,
                    "type": "integer"
                  }
                },
                "required": [
                  "id"
                ]
              },
              "style": "form"
            },
            "confazCest": {
              "in": "query",
              "name": "primaryKey",
              "required": true,
              "schema": {
                "type": "object",
                "properties": {
                  "id": {
                    "x-updatable": true,
                    "x-essential": true,
                    "type": "integer"
                  },
                  "ncm": {
                    "x-updatable": true,
                    "x-essential": true,
                    "type": "integer"
                  }
                },
                "required": [
                  "id",
                  "ncm"
                ]
              },
              "style": "form"
            },
            "employed": {
              "in": "query",
              "name": "primaryKey",
              "required": true,
              "schema": {
                "type": "object",
                "properties": {
                  "rufsGroupOwner": {
                    "x-updatable": true,
                    "x-essential": true,
                    "x-$ref": "#/components/schemas/rufsGroupOwner",
                    "type": "integer"
                  },
                  "person": {
                    "x-updatable": true,
                    "x-essential": true,
                    "x-$ref": "#/components/schemas/person",
                    "type": "string",
                    "maxLength": 18
                  }
                },
                "required": [
                  "rufsGroupOwner",
                  "person"
                ]
              },
              "style": "form"
            },
            "ibgeCity": {
              "in": "query",
              "name": "primaryKey",
              "required": true,
              "schema": {
                "type": "object",
                "properties": {
                  "id": {
                    "x-updatable": true,
                    "x-essential": true,
                    "type": "integer"
                  }
                },
                "required": [
                  "id"
                ]
              },
              "style": "form"
            },
            "ibgeCnae": {
              "in": "query",
              "name": "primaryKey",
              "required": true,
              "schema": {
                "type": "object",
                "properties": {
                  "id": {
                    "x-updatable": true,
                    "x-essential": true,
                    "type": "integer"
                  }
                },
                "required": [
                  "id"
                ]
              },
              "style": "form"
            },
            "ibgeUf": {
              "in": "query",
              "name": "primaryKey",
              "required": true,
              "schema": {
                "type": "object",
                "properties": {
                  "id": {
                    "x-updatable": true,
                    "x-essential": true,
                    "type": "integer"
                  }
                },
                "required": [
                  "id"
                ]
              },
              "style": "form"
            },
            "nfeCfop": {
              "in": "query",
              "name": "primaryKey",
              "required": true,
              "schema": {
                "type": "object",
                "properties": {
                  "id": {
                    "x-updatable": true,
                    "x-essential": true,
                    "type": "integer"
                  }
                },
                "required": [
                  "id"
                ]
              },
              "style": "form"
            },
            "nfeStCofins": {
              "in": "query",
              "name": "primaryKey",
              "required": true,
              "schema": {
                "type": "object",
                "properties": {
                  "id": {
                    "x-updatable": true,
                    "x-essential": true,
                    "type": "integer"
                  }
                },
                "required": [
                  "id"
                ]
              },
              "style": "form"
            },
            "nfeStCsosn": {
              "in": "query",
              "name": "primaryKey",
              "required": true,
              "schema": {
                "type": "object",
                "properties": {
                  "id": {
                    "x-updatable": true,
                    "x-essential": true,
                    "type": "integer"
                  }
                },
                "required": [
                  "id"
                ]
              },
              "style": "form"
            },
            "nfeStIcms": {
              "in": "query",
              "name": "primaryKey",
              "required": true,
              "schema": {
                "type": "object",
                "properties": {
                  "id": {
                    "x-updatable": true,
                    "x-essential": true,
                    "type": "integer"
                  }
                },
                "required": [
                  "id"
                ]
              },
              "style": "form"
            },
            "nfeStIcmsDesoneracao": {
              "in": "query",
              "name": "primaryKey",
              "required": true,
              "schema": {
                "type": "object",
                "properties": {
                  "id": {
                    "x-updatable": true,
                    "x-essential": true,
                    "type": "integer"
                  }
                },
                "required": [
                  "id"
                ]
              },
              "style": "form"
            },
            "nfeStIcmsModalidadeBc": {
              "in": "query",
              "name": "primaryKey",
              "required": true,
              "schema": {
                "type": "object",
                "properties": {
                  "id": {
                    "x-updatable": true,
                    "x-essential": true,
                    "type": "integer"
                  }
                },
                "required": [
                  "id"
                ]
              },
              "style": "form"
            },
            "nfeStIcmsModalidadeSt": {
              "in": "query",
              "name": "primaryKey",
              "required": true,
              "schema": {
                "type": "object",
                "properties": {
                  "id": {
                    "x-updatable": true,
                    "x-essential": true,
                    "type": "integer"
                  }
                },
                "required": [
                  "id"
                ]
              },
              "style": "form"
            },
            "nfeStIcmsOrigem": {
              "in": "query",
              "name": "primaryKey",
              "required": true,
              "schema": {
                "type": "object",
                "properties": {
                  "id": {
                    "x-updatable": true,
                    "x-essential": true,
                    "type": "integer"
                  }
                },
                "required": [
                  "id"
                ]
              },
              "style": "form"
            },
            "nfeStIpi": {
              "in": "query",
              "name": "primaryKey",
              "required": true,
              "schema": {
                "type": "object",
                "properties": {
                  "id": {
                    "x-updatable": true,
                    "x-essential": true,
                    "type": "integer"
                  }
                },
                "required": [
                  "id"
                ]
              },
              "style": "form"
            },
            "nfeStIpiEnquadramento": {
              "in": "query",
              "name": "primaryKey",
              "required": true,
              "schema": {
                "type": "object",
                "properties": {
                  "id": {
                    "x-updatable": true,
                    "x-essential": true,
                    "type": "integer"
                  }
                },
                "required": [
                  "id"
                ]
              },
              "style": "form"
            },
            "nfeStIpiOperacao": {
              "in": "query",
              "name": "primaryKey",
              "required": true,
              "schema": {
                "type": "object",
                "properties": {
                  "id": {
                    "x-updatable": true,
                    "x-essential": true,
                    "type": "integer"
                  }
                },
                "required": [
                  "id"
                ]
              },
              "style": "form"
            },
            "nfeStPis": {
              "in": "query",
              "name": "primaryKey",
              "required": true,
              "schema": {
                "type": "object",
                "properties": {
                  "id": {
                    "x-updatable": true,
                    "x-essential": true,
                    "type": "integer"
                  }
                },
                "required": [
                  "id"
                ]
              },
              "style": "form"
            },
            "nfeTaxGroup": {
              "in": "query",
              "name": "primaryKey",
              "required": true,
              "schema": {
                "type": "object",
                "properties": {
                  "ncm": {
                    "x-updatable": true,
                    "x-essential": true,
                    "x-$ref": "#/components/schemas/camexNcm",
                    "type": "integer"
                  },
                  "city": {
                    "default": 4304606,
                    "x-updatable": true,
                    "x-essential": true,
                    "x-$ref": "#/components/schemas/ibgeCity",
                    "type": "integer"
                  }
                },
                "required": [
                  "ncm",
                  "city"
                ]
              },
              "style": "form"
            },
            "nfseCodService": {
              "in": "query",
              "name": "primaryKey",
              "required": true,
              "schema": {
                "type": "object",
                "properties": {
                  "id": {
                    "x-updatable": true,
                    "x-essential": true,
                    "type": "integer"
                  }
                },
                "required": [
                  "id"
                ]
              },
              "style": "form"
            },
            "paymentType": {
              "in": "query",
              "name": "primaryKey",
              "required": true,
              "schema": {
                "type": "object",
                "properties": {
                  "id": {
                    "x-updatable": true,
                    "x-essential": true,
                    "type": "integer"
                  }
                },
                "required": [
                  "id"
                ]
              },
              "style": "form"
            },
            "person": {
              "in": "query",
              "name": "primaryKey",
              "required": true,
              "schema": {
                "type": "object",
                "properties": {
                  "cnpjCpf": {
                    "x-updatable": true,
                    "x-essential": true,
                    "type": "string",
                    "maxLength": 18
                  }
                },
                "required": [
                  "cnpjCpf"
                ]
              },
              "style": "form"
            },
            "product": {
              "in": "query",
              "name": "primaryKey",
              "required": true,
              "schema": {
                "type": "object",
                "properties": {
                  "id": {
                    "x-updatable": true,
                    "x-identityGeneration": "BY DEFAULT",
                    "x-essential": true,
                    "type": "integer"
                  }
                },
                "required": [
                  "id"
                ]
              },
              "style": "form"
            },
            "request": {
              "in": "query",
              "name": "primaryKey",
              "required": true,
              "schema": {
                "type": "object",
                "properties": {
                  "rufsGroupOwner": {
                    "x-updatable": true,
                    "x-essential": true,
                    "x-$ref": "#/components/schemas/rufsGroupOwner",
                    "type": "integer"
                  },
                  "id": {
                    "x-updatable": true,
                    "x-identityGeneration": "BY DEFAULT",
                    "x-essential": true,
                    "type": "integer"
                  }
                },
                "required": [
                  "rufsGroupOwner",
                  "id"
                ]
              },
              "style": "form"
            },
            "requestFreight": {
              "in": "query",
              "name": "primaryKey",
              "required": true,
              "schema": {
                "type": "object",
                "properties": {
                  "rufsGroupOwner": {
                    "x-updatable": true,
                    "x-essential": true,
                    "x-$ref": "#/components/schemas/rufsGroupOwner",
                    "type": "integer"
                  },
                  "request": {
                    "x-updatable": true,
                    "x-essential": true,
                    "x-$ref": "#/components/schemas/request",
                    "type": "integer"
                  }
                },
                "required": [
                  "rufsGroupOwner",
                  "request"
                ]
              },
              "style": "form"
            },
            "requestNfe": {
              "in": "query",
              "name": "primaryKey",
              "required": true,
              "schema": {
                "type": "object",
                "properties": {
                  "rufsGroupOwner": {
                    "x-updatable": true,
                    "x-essential": true,
                    "x-$ref": "#/components/schemas/rufsGroupOwner",
                    "type": "integer"
                  },
                  "request": {
                    "x-updatable": true,
                    "x-essential": true,
                    "x-$ref": "#/components/schemas/request",
                    "type": "integer"
                  }
                },
                "required": [
                  "rufsGroupOwner",
                  "request"
                ]
              },
              "style": "form"
            },
            "requestPayment": {
              "in": "query",
              "name": "primaryKey",
              "required": true,
              "schema": {
                "type": "object",
                "properties": {
                  "rufsGroupOwner": {
                    "x-updatable": true,
                    "x-essential": true,
                    "x-$ref": "#/components/schemas/rufsGroupOwner",
                    "type": "integer"
                  },
                  "id": {
                    "x-updatable": true,
                    "x-identityGeneration": "BY DEFAULT",
                    "x-essential": true,
                    "type": "integer"
                  }
                },
                "required": [
                  "rufsGroupOwner",
                  "id"
                ]
              },
              "style": "form"
            },
            "requestProduct": {
              "in": "query",
              "name": "primaryKey",
              "required": true,
              "schema": {
                "type": "object",
                "properties": {
                  "rufsGroupOwner": {
                    "x-updatable": true,
                    "x-essential": true,
                    "x-$ref": "#/components/schemas/rufsGroupOwner",
                    "type": "integer"
                  },
                  "id": {
                    "x-updatable": true,
                    "x-identityGeneration": "BY DEFAULT",
                    "x-essential": true,
                    "type": "integer"
                  }
                },
                "required": [
                  "rufsGroupOwner",
                  "id"
                ]
              },
              "style": "form"
            },
            "requestService": {
              "in": "query",
              "name": "primaryKey",
              "required": true,
              "schema": {
                "type": "object",
                "properties": {
                  "rufsGroupOwner": {
                    "x-updatable": true,
                    "x-essential": true,
                    "x-$ref": "#/components/schemas/rufsGroupOwner",
                    "type": "integer"
                  },
                  "id": {
                    "x-updatable": true,
                    "x-identityGeneration": "BY DEFAULT",
                    "x-essential": true,
                    "type": "integer"
                  }
                },
                "required": [
                  "rufsGroupOwner",
                  "id"
                ]
              },
              "style": "form"
            },
            "requestState": {
              "in": "query",
              "name": "primaryKey",
              "required": true,
              "schema": {
                "type": "object",
                "properties": {
                  "id": {
                    "x-updatable": true,
                    "x-identityGeneration": "BY DEFAULT",
                    "x-essential": true,
                    "type": "integer"
                  }
                },
                "required": [
                  "id"
                ]
              },
              "style": "form"
            },
            "requestType": {
              "in": "query",
              "name": "primaryKey",
              "required": true,
              "schema": {
                "type": "object",
                "properties": {
                  "id": {
                    "x-updatable": true,
                    "x-identityGeneration": "BY DEFAULT",
                    "x-essential": true,
                    "type": "integer"
                  }
                },
                "required": [
                  "id"
                ]
              },
              "style": "form"
            },
            "rufsGroup": {
              "in": "query",
              "name": "primaryKey",
              "required": true,
              "schema": {
                "type": "object",
                "required": [
                  "id"
                ]
              },
              "style": "form"
            },
            "rufsGroupOwner": {
              "in": "query",
              "name": "primaryKey",
              "required": true,
              "schema": {
                "type": "object",
                "required": [
                  "id"
                ]
              },
              "style": "form"
            },
            "rufsGroupUser": {
              "in": "query",
              "name": "primaryKey",
              "required": true,
              "schema": {
                "type": "object",
                "required": [
                  "rufsUser",
                  "rufsGroup"
                ]
              },
              "style": "form"
            },
            "rufsUser": {
              "in": "query",
              "name": "primaryKey",
              "required": true,
              "schema": {
                "type": "object",
                "required": [
                  "id"
                ]
              },
              "style": "form"
            },
            "service": {
              "in": "query",
              "name": "primaryKey",
              "required": true,
              "schema": {
                "type": "object",
                "properties": {
                  "id": {
                    "x-updatable": true,
                    "x-identityGeneration": "BY DEFAULT",
                    "x-essential": true,
                    "type": "integer"
                  }
                },
                "required": [
                  "id"
                ]
              },
              "style": "form"
            },
            "stock": {
              "in": "query",
              "name": "primaryKey",
              "required": true,
              "schema": {
                "type": "object",
                "properties": {
                  "rufsGroupOwner": {
                    "x-updatable": true,
                    "x-essential": true,
                    "x-$ref": "#/components/schemas/rufsGroupOwner",
                    "type": "integer"
                  },
                  "id": {
                    "x-updatable": true,
                    "x-essential": true,
                    "x-$ref": "#/components/schemas/product",
                    "type": "integer"
                  }
                },
                "required": [
                  "rufsGroupOwner",
                  "id"
                ]
              },
              "style": "form"
            },
            "stockAction": {
              "in": "query",
              "name": "primaryKey",
              "required": true,
              "schema": {
                "type": "object",
                "properties": {
                  "id": {
                    "x-updatable": true,
                    "x-identityGeneration": "BY DEFAULT",
                    "x-essential": true,
                    "type": "integer"
                  }
                },
                "required": [
                  "id"
                ]
              },
              "style": "form"
            }
          },
          "requestBodies": {
            "login": {
              "content": {
                "application/json": {
                  "schema": {
                    "type": "object",
                    "properties": {
                      "user": {
                        "type": "string"
                      },
                      "password": {
                        "type": "string"
                      }
                    },
                    "required": [
                      "user",
                      "password"
                    ]
                  }
                }
              },
              "required": true
            },
            "account": {
              "content": {
                "application/json": {
                  "schema": {
                    "$ref": "#/components/schemas/account"
                  }
                }
              },
              "required": true
            },
            "bacenCountry": {
              "content": {
                "application/json": {
                  "schema": {
                    "$ref": "#/components/schemas/bacenCountry"
                  }
                }
              },
              "required": true
            },
            "barcode": {
              "content": {
                "application/json": {
                  "schema": {
                    "$ref": "#/components/schemas/barcode"
                  }
                }
              },
              "required": true
            },
            "camexNcm": {
              "content": {
                "application/json": {
                  "schema": {
                    "$ref": "#/components/schemas/camexNcm"
                  }
                }
              },
              "required": true
            },
            "confazCest": {
              "content": {
                "application/json": {
                  "schema": {
                    "$ref": "#/components/schemas/confazCest"
                  }
                }
              },
              "required": true
            },
            "employed": {
              "content": {
                "application/json": {
                  "schema": {
                    "$ref": "#/components/schemas/employed"
                  }
                }
              },
              "required": true
            },
            "ibgeCity": {
              "content": {
                "application/json": {
                  "schema": {
                    "$ref": "#/components/schemas/ibgeCity"
                  }
                }
              },
              "required": true
            },
            "ibgeCnae": {
              "content": {
                "application/json": {
                  "schema": {
                    "$ref": "#/components/schemas/ibgeCnae"
                  }
                }
              },
              "required": true
            },
            "ibgeUf": {
              "content": {
                "application/json": {
                  "schema": {
                    "$ref": "#/components/schemas/ibgeUf"
                  }
                }
              },
              "required": true
            },
            "nfeCfop": {
              "content": {
                "application/json": {
                  "schema": {
                    "$ref": "#/components/schemas/nfeCfop"
                  }
                }
              },
              "required": true
            },
            "nfeStCofins": {
              "content": {
                "application/json": {
                  "schema": {
                    "$ref": "#/components/schemas/nfeStCofins"
                  }
                }
              },
              "required": true
            },
            "nfeStCsosn": {
              "content": {
                "application/json": {
                  "schema": {
                    "$ref": "#/components/schemas/nfeStCsosn"
                  }
                }
              },
              "required": true
            },
            "nfeStIcms": {
              "content": {
                "application/json": {
                  "schema": {
                    "$ref": "#/components/schemas/nfeStIcms"
                  }
                }
              },
              "required": true
            },
            "nfeStIcmsDesoneracao": {
              "content": {
                "application/json": {
                  "schema": {
                    "$ref": "#/components/schemas/nfeStIcmsDesoneracao"
                  }
                }
              },
              "required": true
            },
            "nfeStIcmsModalidadeBc": {
              "content": {
                "application/json": {
                  "schema": {
                    "$ref": "#/components/schemas/nfeStIcmsModalidadeBc"
                  }
                }
              },
              "required": true
            },
            "nfeStIcmsModalidadeSt": {
              "content": {
                "application/json": {
                  "schema": {
                    "$ref": "#/components/schemas/nfeStIcmsModalidadeSt"
                  }
                }
              },
              "required": true
            },
            "nfeStIcmsOrigem": {
              "content": {
                "application/json": {
                  "schema": {
                    "$ref": "#/components/schemas/nfeStIcmsOrigem"
                  }
                }
              },
              "required": true
            },
            "nfeStIpi": {
              "content": {
                "application/json": {
                  "schema": {
                    "$ref": "#/components/schemas/nfeStIpi"
                  }
                }
              },
              "required": true
            },
            "nfeStIpiEnquadramento": {
              "content": {
                "application/json": {
                  "schema": {
                    "$ref": "#/components/schemas/nfeStIpiEnquadramento"
                  }
                }
              },
              "required": true
            },
            "nfeStIpiOperacao": {
              "content": {
                "application/json": {
                  "schema": {
                    "$ref": "#/components/schemas/nfeStIpiOperacao"
                  }
                }
              },
              "required": true
            },
            "nfeStPis": {
              "content": {
                "application/json": {
                  "schema": {
                    "$ref": "#/components/schemas/nfeStPis"
                  }
                }
              },
              "required": true
            },
            "nfeTaxGroup": {
              "content": {
                "application/json": {
                  "schema": {
                    "$ref": "#/components/schemas/nfeTaxGroup"
                  }
                }
              },
              "required": true
            },
            "nfseCodService": {
              "content": {
                "application/json": {
                  "schema": {
                    "$ref": "#/components/schemas/nfseCodService"
                  }
                }
              },
              "required": true
            },
            "paymentType": {
              "content": {
                "application/json": {
                  "schema": {
                    "$ref": "#/components/schemas/paymentType"
                  }
                }
              },
              "required": true
            },
            "person": {
              "content": {
                "application/json": {
                  "schema": {
                    "$ref": "#/components/schemas/person"
                  }
                }
              },
              "required": true
            },
            "product": {
              "content": {
                "application/json": {
                  "schema": {
                    "$ref": "#/components/schemas/product"
                  }
                }
              },
              "required": true
            },
            "request": {
              "content": {
                "application/json": {
                  "schema": {
                    "$ref": "#/components/schemas/request"
                  }
                }
              },
              "required": true
            },
            "requestFreight": {
              "content": {
                "application/json": {
                  "schema": {
                    "$ref": "#/components/schemas/requestFreight"
                  }
                }
              },
              "required": true
            },
            "requestNfe": {
              "content": {
                "application/json": {
                  "schema": {
                    "$ref": "#/components/schemas/requestNfe"
                  }
                }
              },
              "required": true
            },
            "requestPayment": {
              "content": {
                "application/json": {
                  "schema": {
                    "$ref": "#/components/schemas/requestPayment"
                  }
                }
              },
              "required": true
            },
            "requestProduct": {
              "content": {
                "application/json": {
                  "schema": {
                    "$ref": "#/components/schemas/requestProduct"
                  }
                }
              },
              "required": true
            },
            "requestService": {
              "content": {
                "application/json": {
                  "schema": {
                    "$ref": "#/components/schemas/requestService"
                  }
                }
              },
              "required": true
            },
            "requestState": {
              "content": {
                "application/json": {
                  "schema": {
                    "$ref": "#/components/schemas/requestState"
                  }
                }
              },
              "required": true
            },
            "requestType": {
              "content": {
                "application/json": {
                  "schema": {
                    "$ref": "#/components/schemas/requestType"
                  }
                }
              },
              "required": true
            },
            "rufsGroup": {
              "content": {
                "application/json": {
                  "schema": {
                    "$ref": "#/components/schemas/rufsGroup"
                  }
                }
              },
              "required": true
            },
            "rufsGroupOwner": {
              "content": {
                "application/json": {
                  "schema": {
                    "$ref": "#/components/schemas/rufsGroupOwner"
                  }
                }
              },
              "required": true
            },
            "rufsGroupUser": {
              "content": {
                "application/json": {
                  "schema": {
                    "$ref": "#/components/schemas/rufsGroupUser"
                  }
                }
              },
              "required": true
            },
            "rufsUser": {
              "content": {
                "application/json": {
                  "schema": {
                    "$ref": "#/components/schemas/rufsUser"
                  }
                }
              },
              "required": true
            },
            "service": {
              "content": {
                "application/json": {
                  "schema": {
                    "$ref": "#/components/schemas/service"
                  }
                }
              },
              "required": true
            },
            "stock": {
              "content": {
                "application/json": {
                  "schema": {
                    "$ref": "#/components/schemas/stock"
                  }
                }
              },
              "required": true
            },
            "stockAction": {
              "content": {
                "application/json": {
                  "schema": {
                    "$ref": "#/components/schemas/stockAction"
                  }
                }
              },
              "required": true
            }
          },
          "schemas": {
            "login": {
              "type": "object",
              "properties": {
                "tokenPayload": {
                  "type": "string"
                }
              },
              "required": [
                "tokenPayload"
              ]
            },
            "account": {
              "x-primaryKeys": [
                "rufsGroupOwner",
                "id"
              ],
              "x-uniqueKeys": {
                "accountBankAgencyNumberKey": [
                  "bank",
                  "agency",
                  "number"
                ],
                "accountPersonDescriptionKey": [
                  "person",
                  "description"
                ]
              },
              "x-foreignKeys": {},
              "type": "object",
              "properties": {
                "rufsGroupOwner": {
                  "x-updatable": true,
                  "x-essential": true,
                  "x-$ref": "#/components/schemas/rufsGroupOwner",
                  "type": "integer"
                },
                "id": {
                  "x-updatable": true,
                  "x-identityGeneration": "BY DEFAULT",
                  "x-essential": true,
                  "type": "integer"
                },
                "person": {
                  "x-updatable": true,
                  "x-essential": true,
                  "x-$ref": "#/components/schemas/person",
                  "type": "string",
                  "maxLength": 18
                },
                "bank": {
                  "nullable": true,
                  "x-updatable": true,
                  "x-$ref": "#/components/schemas/person",
                  "type": "string",
                  "maxLength": 18
                },
                "agency": {
                  "nullable": true,
                  "x-updatable": true,
                  "type": "string",
                  "maxLength": 20
                },
                "number": {
                  "nullable": true,
                  "x-updatable": true,
                  "type": "string",
                  "maxLength": 20
                },
                "description": {
                  "nullable": true,
                  "x-updatable": true,
                  "type": "string",
                  "maxLength": 255
                }
              },
              "required": [
                "rufsGroupOwner",
                "id",
                "person"
              ]
            },
            "bacenCountry": {
              "x-primaryKeys": [
                "id"
              ],
              "x-uniqueKeys": {
                "bacenCountryAbrKey": [
                  "abr"
                ],
                "bacenCountryNameKey": [
                  "name"
                ],
                "bacenCountryNamePtKey": [
                  "namePt"
                ]
              },
              "x-foreignKeys": {},
              "type": "object",
              "properties": {
                "id": {
                  "default": 1058,
                  "x-updatable": true,
                  "x-essential": true,
                  "type": "integer"
                },
                "name": {
                  "default": "Brazil::character varying",
                  "x-updatable": true,
                  "x-essential": true,
                  "type": "string",
                  "maxLength": 100
                },
                "namePt": {
                  "default": "Brasil::character varying",
                  "x-updatable": true,
                  "x-essential": true,
                  "type": "string",
                  "maxLength": 100
                },
                "abr": {
                  "default": "BR::character varying",
                  "x-updatable": true,
                  "x-essential": true,
                  "type": "string",
                  "maxLength": 2
                }
              },
              "required": [
                "id",
                "name",
                "namePt",
                "abr"
              ]
            },
            "barcode": {
              "x-primaryKeys": [
                "number"
              ],
              "x-uniqueKeys": {},
              "x-foreignKeys": {},
              "type": "object",
              "properties": {
                "number": {
                  "x-updatable": true,
                  "x-essential": true,
                  "type": "string",
                  "maxLength": 14
                },
                "manufacturer": {
                  "nullable": true,
                  "x-updatable": true,
                  "type": "string",
                  "maxLength": 64
                },
                "product": {
                  "nullable": true,
                  "x-updatable": true,
                  "x-$ref": "#/components/schemas/product",
                  "type": "integer"
                }
              },
              "required": [
                "number"
              ]
            },
            "camexNcm": {
              "x-primaryKeys": [
                "id"
              ],
              "x-uniqueKeys": {},
              "x-foreignKeys": {},
              "type": "object",
              "properties": {
                "id": {
                  "x-updatable": true,
                  "x-essential": true,
                  "type": "integer"
                },
                "name": {
                  "nullable": true,
                  "x-updatable": true,
                  "type": "string",
                  "maxLength": 1024
                },
                "unit": {
                  "nullable": true,
                  "x-updatable": true,
                  "type": "string",
                  "maxLength": 16
                },
                "tec": {
                  "nullable": true,
                  "x-updatable": true,
                  "type": "integer"
                }
              },
              "required": [
                "id"
              ]
            },
            "confazCest": {
              "x-primaryKeys": [
                "id",
                "ncm"
              ],
              "x-uniqueKeys": {},
              "x-foreignKeys": {},
              "type": "object",
              "properties": {
                "id": {
                  "x-updatable": true,
                  "x-essential": true,
                  "type": "integer"
                },
                "ncm": {
                  "x-updatable": true,
                  "x-essential": true,
                  "type": "integer"
                },
                "name": {
                  "nullable": true,
                  "x-updatable": true,
                  "type": "string",
                  "maxLength": 1024
                }
              },
              "required": [
                "id",
                "ncm"
              ]
            },
            "employed": {
              "x-primaryKeys": [
                "rufsGroupOwner",
                "person"
              ],
              "x-uniqueKeys": {},
              "x-foreignKeys": {},
              "type": "object",
              "properties": {
                "rufsGroupOwner": {
                  "x-updatable": true,
                  "x-essential": true,
                  "x-$ref": "#/components/schemas/rufsGroupOwner",
                  "type": "integer"
                },
                "person": {
                  "x-updatable": true,
                  "x-essential": true,
                  "x-$ref": "#/components/schemas/person",
                  "type": "string",
                  "maxLength": 18
                },
                "hourlyPayValue": {
                  "nullable": true,
                  "x-updatable": true,
                  "x-scale": 3,
                  "x-precision": 9,
                  "type": "number"
                }
              },
              "required": [
                "rufsGroupOwner",
                "person"
              ]
            },
            "ibgeCity": {
              "x-primaryKeys": [
                "id"
              ],
              "x-uniqueKeys": {
                "ibgeCityNameUfKey": [
                  "name",
                  "uf"
                ]
              },
              "x-foreignKeys": {},
              "type": "object",
              "properties": {
                "id": {
                  "x-updatable": true,
                  "x-essential": true,
                  "type": "integer"
                },
                "name": {
                  "x-updatable": true,
                  "x-essential": true,
                  "type": "string",
                  "maxLength": 100
                },
                "uf": {
                  "nullable": true,
                  "default": 43,
                  "x-updatable": true,
                  "x-$ref": "#/components/schemas/ibgeUf",
                  "type": "integer"
                }
              },
              "required": [
                "id",
                "name"
              ]
            },
            "ibgeCnae": {
              "x-primaryKeys": [
                "id"
              ],
              "x-uniqueKeys": {
                "ibgeCnaeNameKey": [
                  "name"
                ]
              },
              "x-foreignKeys": {},
              "type": "object",
              "properties": {
                "id": {
                  "x-updatable": true,
                  "x-essential": true,
                  "type": "integer"
                },
                "name": {
                  "x-updatable": true,
                  "x-essential": true,
                  "type": "string",
                  "maxLength": 512
                }
              },
              "required": [
                "id",
                "name"
              ]
            },
            "ibgeUf": {
              "x-primaryKeys": [
                "id"
              ],
              "x-uniqueKeys": {
                "ibgeUfAbrKey": [
                  "abr"
                ],
                "ibgeUfNameKey": [
                  "name"
                ]
              },
              "x-foreignKeys": {},
              "type": "object",
              "properties": {
                "id": {
                  "x-updatable": true,
                  "x-essential": true,
                  "type": "integer"
                },
                "country": {
                  "nullable": true,
                  "default": 1058,
                  "x-updatable": true,
                  "x-$ref": "#/components/schemas/bacenCountry",
                  "type": "integer"
                },
                "name": {
                  "x-updatable": true,
                  "x-essential": true,
                  "type": "string",
                  "maxLength": 100
                },
                "abr": {
                  "default": "RS::character varying",
                  "x-updatable": true,
                  "x-essential": true,
                  "type": "string",
                  "maxLength": 2
                },
                "ddd": {
                  "nullable": true,
                  "default": "NULL::character varying",
                  "x-updatable": true,
                  "type": "string",
                  "maxLength": 50
                }
              },
              "required": [
                "id",
                "name",
                "abr"
              ]
            },
            "nfeCfop": {
              "x-primaryKeys": [
                "id"
              ],
              "x-uniqueKeys": {},
              "x-foreignKeys": {},
              "type": "object",
              "properties": {
                "id": {
                  "x-updatable": true,
                  "x-essential": true,
                  "type": "integer"
                },
                "name": {
                  "nullable": true,
                  "x-updatable": true,
                  "type": "string",
                  "maxLength": 1024
                },
                "indNfe": {
                  "nullable": true,
                  "default": 1,
                  "x-updatable": true,
                  "type": "integer"
                },
                "indComunica": {
                  "nullable": true,
                  "default": 0,
                  "x-updatable": true,
                  "type": "integer"
                },
                "indTransp": {
                  "nullable": true,
                  "default": 0,
                  "x-updatable": true,
                  "type": "integer"
                },
                "indDevol": {
                  "nullable": true,
                  "default": 0,
                  "x-updatable": true,
                  "type": "integer"
                }
              },
              "required": [
                "id"
              ]
            },
            "nfeStCofins": {
              "x-primaryKeys": [
                "id"
              ],
              "x-uniqueKeys": {},
              "x-foreignKeys": {},
              "type": "object",
              "properties": {
                "id": {
                  "x-updatable": true,
                  "x-essential": true,
                  "type": "integer"
                },
                "name": {
                  "nullable": true,
                  "x-updatable": true,
                  "type": "string",
                  "maxLength": 1024
                }
              },
              "required": [
                "id"
              ]
            },
            "nfeStCsosn": {
              "x-primaryKeys": [
                "id"
              ],
              "x-uniqueKeys": {},
              "x-foreignKeys": {},
              "type": "object",
              "properties": {
                "id": {
                  "x-updatable": true,
                  "x-essential": true,
                  "type": "integer"
                },
                "name": {
                  "nullable": true,
                  "x-updatable": true,
                  "type": "string",
                  "maxLength": 1024
                },
                "description": {
                  "nullable": true,
                  "x-updatable": true,
                  "type": "string",
                  "maxLength": 1024
                }
              },
              "required": [
                "id"
              ]
            },
            "nfeStIcms": {
              "x-primaryKeys": [
                "id"
              ],
              "x-uniqueKeys": {},
              "x-foreignKeys": {},
              "type": "object",
              "properties": {
                "id": {
                  "x-updatable": true,
                  "x-essential": true,
                  "type": "integer"
                },
                "name": {
                  "nullable": true,
                  "x-updatable": true,
                  "type": "string",
                  "maxLength": 255
                }
              },
              "required": [
                "id"
              ]
            },
            "nfeStIcmsDesoneracao": {
              "x-primaryKeys": [
                "id"
              ],
              "x-uniqueKeys": {},
              "x-foreignKeys": {},
              "type": "object",
              "properties": {
                "id": {
                  "x-updatable": true,
                  "x-essential": true,
                  "type": "integer"
                },
                "name": {
                  "nullable": true,
                  "x-updatable": true,
                  "type": "string",
                  "maxLength": 1024
                }
              },
              "required": [
                "id"
              ]
            },
            "nfeStIcmsModalidadeBc": {
              "x-primaryKeys": [
                "id"
              ],
              "x-uniqueKeys": {},
              "x-foreignKeys": {},
              "type": "object",
              "properties": {
                "id": {
                  "x-updatable": true,
                  "x-essential": true,
                  "type": "integer"
                },
                "name": {
                  "nullable": true,
                  "x-updatable": true,
                  "type": "string",
                  "maxLength": 1024
                }
              },
              "required": [
                "id"
              ]
            },
            "nfeStIcmsModalidadeSt": {
              "x-primaryKeys": [
                "id"
              ],
              "x-uniqueKeys": {},
              "x-foreignKeys": {},
              "type": "object",
              "properties": {
                "id": {
                  "x-updatable": true,
                  "x-essential": true,
                  "type": "integer"
                },
                "name": {
                  "nullable": true,
                  "x-updatable": true,
                  "type": "string",
                  "maxLength": 1024
                }
              },
              "required": [
                "id"
              ]
            },
            "nfeStIcmsOrigem": {
              "x-primaryKeys": [
                "id"
              ],
              "x-uniqueKeys": {},
              "x-foreignKeys": {},
              "type": "object",
              "properties": {
                "id": {
                  "x-updatable": true,
                  "x-essential": true,
                  "type": "integer"
                },
                "name": {
                  "nullable": true,
                  "x-updatable": true,
                  "type": "string",
                  "maxLength": 255
                }
              },
              "required": [
                "id"
              ]
            },
            "nfeStIpi": {
              "x-primaryKeys": [
                "id"
              ],
              "x-uniqueKeys": {},
              "x-foreignKeys": {},
              "type": "object",
              "properties": {
                "id": {
                  "x-updatable": true,
                  "x-essential": true,
                  "type": "integer"
                },
                "name": {
                  "nullable": true,
                  "x-updatable": true,
                  "type": "string",
                  "maxLength": 255
                }
              },
              "required": [
                "id"
              ]
            },
            "nfeStIpiEnquadramento": {
              "x-primaryKeys": [
                "id"
              ],
              "x-uniqueKeys": {},
              "x-foreignKeys": {},
              "type": "object",
              "properties": {
                "id": {
                  "x-updatable": true,
                  "x-essential": true,
                  "type": "integer"
                },
                "name": {
                  "nullable": true,
                  "x-updatable": true,
                  "type": "string",
                  "maxLength": 1024
                },
                "ipiOperacao": {
                  "nullable": true,
                  "x-updatable": true,
                  "x-$ref": "#/components/schemas/nfeStIpiOperacao",
                  "type": "integer"
                }
              },
              "required": [
                "id"
              ]
            },
            "nfeStIpiOperacao": {
              "x-primaryKeys": [
                "id"
              ],
              "x-uniqueKeys": {},
              "x-foreignKeys": {},
              "type": "object",
              "properties": {
                "id": {
                  "x-updatable": true,
                  "x-essential": true,
                  "type": "integer"
                },
                "name": {
                  "nullable": true,
                  "x-updatable": true,
                  "type": "string",
                  "maxLength": 255
                }
              },
              "required": [
                "id"
              ]
            },
            "nfeStPis": {
              "x-primaryKeys": [
                "id"
              ],
              "x-uniqueKeys": {},
              "x-foreignKeys": {},
              "type": "object",
              "properties": {
                "id": {
                  "x-updatable": true,
                  "x-essential": true,
                  "type": "integer"
                },
                "name": {
                  "nullable": true,
                  "x-updatable": true,
                  "type": "string",
                  "maxLength": 255
                }
              },
              "required": [
                "id"
              ]
            },
            "nfeTaxGroup": {
              "x-primaryKeys": [
                "ncm",
                "city"
              ],
              "x-uniqueKeys": {},
              "x-foreignKeys": {},
              "type": "object",
              "properties": {
                "ncm": {
                  "x-updatable": true,
                  "x-essential": true,
                  "x-$ref": "#/components/schemas/camexNcm",
                  "type": "integer"
                },
                "city": {
                  "default": 4304606,
                  "x-updatable": true,
                  "x-essential": true,
                  "x-$ref": "#/components/schemas/ibgeCity",
                  "type": "integer"
                },
                "cstIpi": {
                  "nullable": true,
                  "x-updatable": true,
                  "x-$ref": "#/components/schemas/nfeStIpi",
                  "type": "integer"
                },
                "cstIcms": {
                  "nullable": true,
                  "x-updatable": true,
                  "x-$ref": "#/components/schemas/nfeStIcms",
                  "type": "integer"
                },
                "cstPis": {
                  "nullable": true,
                  "x-updatable": true,
                  "x-$ref": "#/components/schemas/nfeStPis",
                  "type": "integer"
                },
                "cstCofins": {
                  "nullable": true,
                  "x-updatable": true,
                  "x-$ref": "#/components/schemas/nfeStCofins",
                  "type": "integer"
                },
                "taxSimples": {
                  "nullable": true,
                  "default": 0.0,
                  "x-updatable": true,
                  "x-scale": 2,
                  "x-precision": 5,
                  "type": "number"
                },
                "taxIpi": {
                  "nullable": true,
                  "default": 0.0,
                  "x-updatable": true,
                  "x-scale": 2,
                  "x-precision": 5,
                  "type": "number"
                },
                "taxIcms": {
                  "nullable": true,
                  "default": 0.0,
                  "x-updatable": true,
                  "x-scale": 2,
                  "x-precision": 5,
                  "type": "number"
                },
                "taxPis": {
                  "nullable": true,
                  "default": 0.0,
                  "x-updatable": true,
                  "x-scale": 2,
                  "x-precision": 5,
                  "type": "number"
                },
                "taxCofins": {
                  "nullable": true,
                  "default": 0.0,
                  "x-updatable": true,
                  "x-scale": 2,
                  "x-precision": 5,
                  "type": "number"
                },
                "taxIssqn": {
                  "nullable": true,
                  "default": 0.0,
                  "x-updatable": true,
                  "x-scale": 2,
                  "x-precision": 5,
                  "type": "number"
                }
              },
              "required": [
                "ncm",
                "city"
              ]
            },
            "nfseCodService": {
              "x-primaryKeys": [
                "id"
              ],
              "x-uniqueKeys": {},
              "x-foreignKeys": {},
              "type": "object",
              "properties": {
                "id": {
                  "x-updatable": true,
                  "x-essential": true,
                  "type": "integer"
                },
                "name": {
                  "nullable": true,
                  "x-updatable": true,
                  "type": "string",
                  "maxLength": 1024
                }
              },
              "required": [
                "id"
              ]
            },
            "paymentType": {
              "x-primaryKeys": [
                "id"
              ],
              "x-uniqueKeys": {
                "paymentTypeNameKey": [
                  "name"
                ]
              },
              "x-foreignKeys": {},
              "type": "object",
              "properties": {
                "id": {
                  "x-updatable": true,
                  "x-essential": true,
                  "type": "integer"
                },
                "name": {
                  "x-updatable": true,
                  "x-essential": true,
                  "type": "string",
                  "maxLength": 50
                },
                "description": {
                  "nullable": true,
                  "x-updatable": true,
                  "type": "string",
                  "maxLength": 255
                }
              },
              "required": [
                "id",
                "name"
              ]
            },
            "person": {
              "x-primaryKeys": [
                "cnpjCpf"
              ],
              "x-uniqueKeys": {
                "personFantasyKey": [
                  "fantasy"
                ],
                "personIeRgKey": [
                  "ieRg"
                ],
                "personNameKey": [
                  "name"
                ]
              },
              "x-foreignKeys": {},
              "type": "object",
              "properties": {
                "cnpjCpf": {
                  "x-updatable": true,
                  "x-essential": true,
                  "type": "string",
                  "maxLength": 18
                },
                "ieRg": {
                  "nullable": true,
                  "x-updatable": true,
                  "type": "string",
                  "maxLength": 12
                },
                "name": {
                  "nullable": true,
                  "x-updatable": true,
                  "type": "string",
                  "maxLength": 60
                },
                "additionalData": {
                  "nullable": true,
                  "x-updatable": true,
                  "type": "string",
                  "maxLength": 255
                },
                "country": {
                  "nullable": true,
                  "default": 1058,
                  "x-updatable": true,
                  "x-$ref": "#/components/schemas/bacenCountry",
                  "type": "integer"
                },
                "zip": {
                  "nullable": true,
                  "x-updatable": true,
                  "type": "string",
                  "maxLength": 8
                },
                "uf": {
                  "nullable": true,
                  "default": 43,
                  "x-updatable": true,
                  "x-$ref": "#/components/schemas/ibgeUf",
                  "type": "integer"
                },
                "city": {
                  "nullable": true,
                  "default": 4304606,
                  "x-updatable": true,
                  "x-$ref": "#/components/schemas/ibgeCity",
                  "type": "integer"
                },
                "district": {
                  "nullable": true,
                  "x-updatable": true,
                  "type": "string",
                  "maxLength": 60
                },
                "address": {
                  "nullable": true,
                  "x-updatable": true,
                  "type": "string",
                  "maxLength": 60
                },
                "addressNumber": {
                  "nullable": true,
                  "x-updatable": true,
                  "type": "string",
                  "maxLength": 60
                },
                "complement": {
                  "nullable": true,
                  "x-updatable": true,
                  "type": "string",
                  "maxLength": 60
                },
                "email": {
                  "nullable": true,
                  "x-updatable": true,
                  "type": "string",
                  "maxLength": 60
                },
                "phone": {
                  "nullable": true,
                  "x-updatable": true,
                  "type": "string",
                  "maxLength": 14
                },
                "cnae": {
                  "nullable": true,
                  "x-updatable": true,
                  "x-$ref": "#/components/schemas/ibgeCnae",
                  "type": "integer"
                },
                "crt": {
                  "nullable": true,
                  "default": 1,
                  "x-updatable": true,
                  "type": "integer"
                },
                "suframa": {
                  "nullable": true,
                  "x-updatable": true,
                  "type": "string",
                  "maxLength": 9
                },
                "im": {
                  "nullable": true,
                  "x-updatable": true,
                  "type": "string",
                  "maxLength": 15
                },
                "site": {
                  "nullable": true,
                  "x-updatable": true,
                  "type": "string",
                  "maxLength": 100
                },
                "fantasy": {
                  "nullable": true,
                  "x-updatable": true,
                  "type": "string",
                  "maxLength": 100
                }
              },
              "required": [
                "cnpjCpf"
              ]
            },
            "product": {
              "x-primaryKeys": [
                "id"
              ],
              "x-uniqueKeys": {
                "productNameKey": [
                  "name"
                ]
              },
              "x-foreignKeys": {},
              "type": "object",
              "properties": {
                "id": {
                  "x-updatable": true,
                  "x-identityGeneration": "BY DEFAULT",
                  "x-essential": true,
                  "type": "integer"
                },
                "ncm": {
                  "nullable": true,
                  "x-updatable": true,
                  "x-$ref": "#/components/schemas/camexNcm",
                  "type": "integer"
                },
                "orig": {
                  "nullable": true,
                  "default": 0,
                  "x-updatable": true,
                  "x-$ref": "#/components/schemas/nfeStIcmsOrigem",
                  "type": "integer"
                },
                "name": {
                  "x-updatable": true,
                  "x-essential": true,
                  "type": "string",
                  "maxLength": 120
                },
                "departament": {
                  "nullable": true,
                  "x-updatable": true,
                  "type": "string",
                  "maxLength": 64
                },
                "model": {
                  "nullable": true,
                  "x-updatable": true,
                  "type": "string",
                  "maxLength": 255
                },
                "description": {
                  "nullable": true,
                  "x-updatable": true,
                  "type": "string",
                  "maxLength": 255
                },
                "weight": {
                  "nullable": true,
                  "default": 0.0,
                  "x-updatable": true,
                  "x-scale": 3,
                  "x-precision": 9,
                  "type": "number"
                },
                "imageUrl": {
                  "nullable": true,
                  "x-updatable": true,
                  "type": "string",
                  "maxLength": 255
                },
                "additionalData": {
                  "nullable": true,
                  "x-updatable": true,
                  "type": "string",
                  "maxLength": 255
                }
              },
              "required": [
                "id",
                "name"
              ]
            },
            "request": {
              "x-primaryKeys": [
                "rufsGroupOwner",
                "id"
              ],
              "x-uniqueKeys": {
                "requestPersonPersonDestDateKey": [
                  "person",
                  "personDest",
                  "date"
                ]
              },
              "x-foreignKeys": {},
              "type": "object",
              "properties": {
                "rufsGroupOwner": {
                  "x-updatable": true,
                  "x-essential": true,
                  "x-$ref": "#/components/schemas/rufsGroupOwner",
                  "type": "integer"
                },
                "id": {
                  "x-updatable": true,
                  "x-identityGeneration": "BY DEFAULT",
                  "x-essential": true,
                  "type": "integer"
                },
                "type": {
                  "x-updatable": true,
                  "x-essential": true,
                  "x-$ref": "#/components/schemas/requestType",
                  "type": "integer"
                },
                "state": {
                  "x-updatable": true,
                  "x-essential": true,
                  "x-$ref": "#/components/schemas/requestState",
                  "type": "integer"
                },
                "person": {
                  "x-updatable": true,
                  "x-essential": true,
                  "x-$ref": "#/components/schemas/person",
                  "type": "string",
                  "maxLength": 18
                },
                "personDest": {
                  "x-updatable": true,
                  "x-essential": true,
                  "x-$ref": "#/components/schemas/person",
                  "type": "string",
                  "maxLength": 18
                },
                "date": {
                  "default": "CURRENT_TIMESTAMP",
                  "x-updatable": true,
                  "x-essential": true,
                  "type": "string",
                  "format": "date-time"
                },
                "additionalData": {
                  "nullable": true,
                  "x-updatable": true,
                  "type": "string",
                  "maxLength": 255
                },
                "productsValue": {
                  "nullable": true,
                  "default": 0.0,
                  "x-updatable": true,
                  "x-scale": 2,
                  "x-precision": 19,
                  "type": "number"
                },
                "servicesValue": {
                  "nullable": true,
                  "default": 0.0,
                  "x-updatable": true,
                  "x-scale": 2,
                  "x-precision": 19,
                  "type": "number"
                },
                "transportValue": {
                  "nullable": true,
                  "default": 0.0,
                  "x-updatable": true,
                  "x-scale": 2,
                  "x-precision": 19,
                  "type": "number"
                },
                "descValue": {
                  "nullable": true,
                  "default": 0.0,
                  "x-updatable": true,
                  "x-scale": 2,
                  "x-precision": 19,
                  "type": "number"
                },
                "sumValue": {
                  "nullable": true,
                  "default": 0.0,
                  "x-updatable": true,
                  "x-scale": 2,
                  "x-precision": 19,
                  "type": "number"
                },
                "paymentsValue": {
                  "nullable": true,
                  "default": 0.0,
                  "x-updatable": true,
                  "x-scale": 2,
                  "x-precision": 19,
                  "type": "number"
                }
              },
              "required": [
                "rufsGroupOwner",
                "id",
                "type",
                "state",
                "person",
                "personDest",
                "date"
              ]
            },
            "requestFreight": {
              "x-primaryKeys": [
                "rufsGroupOwner",
                "request"
              ],
              "x-uniqueKeys": {},
              "x-foreignKeys": {
                "requestFreightRufsGroupOwnerRequestFkey": {
                  "fields": {
                    "request": "id",
                    "rufsGroupOwner": "rufsGroupOwner"
                  },
                  "tableRef": "request"
                }
              },
              "type": "object",
              "properties": {
                "rufsGroupOwner": {
                  "x-updatable": true,
                  "x-essential": true,
                  "x-$ref": "#/components/schemas/rufsGroupOwner",
                  "type": "integer"
                },
                "request": {
                  "x-updatable": true,
                  "x-essential": true,
                  "x-$ref": "#/components/schemas/request",
                  "type": "integer"
                },
                "person": {
                  "nullable": true,
                  "x-updatable": true,
                  "x-$ref": "#/components/schemas/person",
                  "type": "string",
                  "maxLength": 18
                },
                "payBy": {
                  "nullable": true,
                  "default": 0,
                  "x-updatable": true,
                  "type": "integer"
                },
                "licensePlate": {
                  "nullable": true,
                  "x-updatable": true,
                  "type": "string",
                  "maxLength": 7
                },
                "licensePlateUf": {
                  "nullable": true,
                  "default": 43,
                  "x-updatable": true,
                  "x-$ref": "#/components/schemas/ibgeUf",
                  "type": "integer"
                },
                "containersType": {
                  "nullable": true,
                  "default": "Volumes::character varying",
                  "x-updatable": true,
                  "type": "string",
                  "maxLength": 60
                },
                "containersCount": {
                  "nullable": true,
                  "default": 1,
                  "x-updatable": true,
                  "type": "integer"
                },
                "weight": {
                  "nullable": true,
                  "default": 0.0,
                  "x-updatable": true,
                  "x-scale": 3,
                  "x-precision": 9,
                  "type": "number"
                },
                "weightFinal": {
                  "nullable": true,
                  "default": 0.0,
                  "x-updatable": true,
                  "x-scale": 3,
                  "x-precision": 9,
                  "type": "number"
                },
                "logo": {
                  "nullable": true,
                  "x-updatable": true,
                  "type": "string",
                  "maxLength": 60
                },
                "value": {
                  "nullable": true,
                  "default": 0.0,
                  "x-updatable": true,
                  "x-scale": 2,
                  "x-precision": 9,
                  "type": "number"
                }
              },
              "required": [
                "rufsGroupOwner",
                "request"
              ]
            },
            "requestNfe": {
              "x-primaryKeys": [
                "rufsGroupOwner",
                "request"
              ],
              "x-uniqueKeys": {},
              "x-foreignKeys": {
                "requestNfeRufsGroupOwnerRequestFkey": {
                  "fields": {
                    "request": "id",
                    "rufsGroupOwner": "rufsGroupOwner"
                  },
                  "tableRef": "request"
                }
              },
              "type": "object",
              "properties": {
                "rufsGroupOwner": {
                  "x-updatable": true,
                  "x-essential": true,
                  "x-$ref": "#/components/schemas/rufsGroupOwner",
                  "type": "integer"
                },
                "request": {
                  "x-updatable": true,
                  "x-essential": true,
                  "x-$ref": "#/components/schemas/request",
                  "type": "integer"
                },
                "dhemi": {
                  "nullable": true,
                  "default": "CURRENT_TIMESTAMP",
                  "x-updatable": true,
                  "type": "string",
                  "format": "date-time"
                },
                "dhsaient": {
                  "nullable": true,
                  "default": "CURRENT_TIMESTAMP",
                  "x-updatable": true,
                  "type": "string",
                  "format": "date-time"
                },
                "valueIi": {
                  "nullable": true,
                  "default": 0.0,
                  "x-updatable": true,
                  "x-scale": 2,
                  "x-precision": 9,
                  "type": "number"
                },
                "valueIpi": {
                  "nullable": true,
                  "default": 0.0,
                  "x-updatable": true,
                  "x-scale": 2,
                  "x-precision": 9,
                  "type": "number"
                },
                "valuePis": {
                  "nullable": true,
                  "default": 0.0,
                  "x-updatable": true,
                  "x-scale": 2,
                  "x-precision": 9,
                  "type": "number"
                },
                "valueCofins": {
                  "nullable": true,
                  "default": 0.0,
                  "x-updatable": true,
                  "x-scale": 2,
                  "x-precision": 9,
                  "type": "number"
                },
                "valueIcms": {
                  "nullable": true,
                  "default": 0.0,
                  "x-updatable": true,
                  "x-scale": 2,
                  "x-precision": 9,
                  "type": "number"
                },
                "valueIcmsSt": {
                  "nullable": true,
                  "default": 0.0,
                  "x-updatable": true,
                  "x-scale": 2,
                  "x-precision": 9,
                  "type": "number"
                },
                "valueIssqn": {
                  "nullable": true,
                  "default": 0.0,
                  "x-updatable": true,
                  "x-scale": 2,
                  "x-precision": 9,
                  "type": "number"
                },
                "valueTax": {
                  "nullable": true,
                  "default": 0.0,
                  "x-updatable": true,
                  "x-scale": 2,
                  "x-precision": 9,
                  "type": "number"
                },
                "versao": {
                  "nullable": true,
                  "default": "3.10::character varying",
                  "x-updatable": true,
                  "type": "string",
                  "maxLength": 4
                },
                "nfeId": {
                  "nullable": true,
                  "x-updatable": true,
                  "type": "string",
                  "maxLength": 47
                },
                "natop": {
                  "nullable": true,
                  "default": "VENDA::character varying",
                  "x-updatable": true,
                  "type": "string",
                  "maxLength": 60
                },
                "indpag": {
                  "nullable": true,
                  "default": 0,
                  "x-updatable": true,
                  "type": "integer"
                },
                "mod": {
                  "nullable": true,
                  "default": 55,
                  "x-updatable": true,
                  "type": "integer"
                },
                "serie": {
                  "nullable": true,
                  "default": 1,
                  "x-updatable": true,
                  "type": "integer"
                },
                "nnf": {
                  "x-updatable": true,
                  "x-identityGeneration": "BY DEFAULT",
                  "x-essential": true,
                  "type": "integer"
                },
                "iddest": {
                  "nullable": true,
                  "default": 1,
                  "x-updatable": true,
                  "type": "integer"
                },
                "tpimp": {
                  "nullable": true,
                  "default": 1,
                  "x-updatable": true,
                  "type": "integer"
                },
                "tpemis": {
                  "nullable": true,
                  "default": 1,
                  "x-updatable": true,
                  "type": "integer"
                },
                "cdv": {
                  "nullable": true,
                  "x-updatable": true,
                  "type": "integer"
                },
                "tpamb": {
                  "nullable": true,
                  "default": 1,
                  "x-updatable": true,
                  "type": "integer"
                },
                "finnfe": {
                  "nullable": true,
                  "default": 1,
                  "x-updatable": true,
                  "type": "integer"
                },
                "indfinal": {
                  "nullable": true,
                  "default": 1,
                  "x-updatable": true,
                  "type": "integer"
                },
                "indpres": {
                  "nullable": true,
                  "default": 1,
                  "x-updatable": true,
                  "type": "integer"
                },
                "procemi": {
                  "nullable": true,
                  "default": 0,
                  "x-updatable": true,
                  "type": "integer"
                },
                "verproc": {
                  "nullable": true,
                  "default": "1.0.000::character varying",
                  "x-updatable": true,
                  "type": "string",
                  "maxLength": 20
                },
                "indiedest": {
                  "nullable": true,
                  "default": 9,
                  "x-updatable": true,
                  "type": "integer"
                }
              },
              "required": [
                "rufsGroupOwner",
                "request",
                "nnf"
              ]
            },
            "requestPayment": {
              "x-primaryKeys": [
                "rufsGroupOwner",
                "id"
              ],
              "x-uniqueKeys": {
                "requestPaymentRufsGroupOwnerRequestDueDateValueKey": [
                  "rufsGroupOwner",
                  "request",
                  "dueDate",
                  "value"
                ]
              },
              "x-foreignKeys": {
                "requestPaymentRufsGroupOwnerAccountFkey": {
                  "fields": {
                    "account": "id",
                    "rufsGroupOwner": "rufsGroupOwner"
                  },
                  "tableRef": "account"
                },
                "requestPaymentRufsGroupOwnerAccountOtherFkey": {
                  "fields": {
                    "accountOther": "id",
                    "rufsGroupOwner": "rufsGroupOwner"
                  },
                  "tableRef": "account"
                },
                "requestPaymentRufsGroupOwnerRequestFkey": {
                  "fields": {
                    "request": "id",
                    "rufsGroupOwner": "rufsGroupOwner"
                  },
                  "tableRef": "request"
                }
              },
              "type": "object",
              "properties": {
                "rufsGroupOwner": {
                  "x-updatable": true,
                  "x-essential": true,
                  "x-$ref": "#/components/schemas/rufsGroupOwner",
                  "type": "integer"
                },
                "request": {
                  "x-updatable": true,
                  "x-essential": true,
                  "x-$ref": "#/components/schemas/request",
                  "type": "integer"
                },
                "id": {
                  "x-updatable": true,
                  "x-identityGeneration": "BY DEFAULT",
                  "x-essential": true,
                  "type": "integer"
                },
                "type": {
                  "x-updatable": true,
                  "x-essential": true,
                  "x-$ref": "#/components/schemas/paymentType",
                  "type": "integer"
                },
                "value": {
                  "default": 0.0,
                  "x-updatable": true,
                  "x-essential": true,
                  "x-scale": 2,
                  "x-precision": 9,
                  "type": "number"
                },
                "account": {
                  "x-updatable": true,
                  "x-essential": true,
                  "x-$ref": "#/components/schemas/account",
                  "type": "integer"
                },
                "accountOther": {
                  "nullable": true,
                  "x-updatable": true,
                  "x-$ref": "#/components/schemas/account",
                  "type": "integer"
                },
                "number": {
                  "nullable": true,
                  "x-updatable": true,
                  "type": "string",
                  "maxLength": 16
                },
                "dueDate": {
                  "x-updatable": true,
                  "x-essential": true,
                  "type": "string",
                  "format": "date-time"
                },
                "payday": {
                  "nullable": true,
                  "x-updatable": true,
                  "type": "string",
                  "format": "date-time"
                },
                "balance": {
                  "default": 0.0,
                  "x-updatable": true,
                  "x-essential": true,
                  "x-scale": 2,
                  "x-precision": 9,
                  "type": "number"
                }
              },
              "required": [
                "rufsGroupOwner",
                "request",
                "id",
                "type",
                "value",
                "account",
                "dueDate",
                "balance"
              ]
            },
            "requestProduct": {
              "x-primaryKeys": [
                "rufsGroupOwner",
                "id"
              ],
              "x-uniqueKeys": {
                "requestProductRequestProductKey": [
                  "request",
                  "product"
                ]
              },
              "x-foreignKeys": {
                "requestProductRufsGroupOwnerRequestFkey": {
                  "fields": {
                    "request": "id",
                    "rufsGroupOwner": "rufsGroupOwner"
                  },
                  "tableRef": "request"
                }
              },
              "type": "object",
              "properties": {
                "rufsGroupOwner": {
                  "x-updatable": true,
                  "x-essential": true,
                  "x-$ref": "#/components/schemas/rufsGroupOwner",
                  "type": "integer"
                },
                "request": {
                  "x-updatable": true,
                  "x-essential": true,
                  "x-$ref": "#/components/schemas/request",
                  "type": "integer"
                },
                "id": {
                  "x-updatable": true,
                  "x-identityGeneration": "BY DEFAULT",
                  "x-essential": true,
                  "type": "integer"
                },
                "product": {
                  "x-updatable": true,
                  "x-essential": true,
                  "x-$ref": "#/components/schemas/product",
                  "type": "integer"
                },
                "quantity": {
                  "default": 1.0,
                  "x-updatable": true,
                  "x-essential": true,
                  "x-scale": 3,
                  "x-precision": 9,
                  "type": "number"
                },
                "value": {
                  "x-updatable": true,
                  "x-essential": true,
                  "x-scale": 3,
                  "x-precision": 9,
                  "type": "number"
                },
                "valueItem": {
                  "nullable": true,
                  "default": 0.0,
                  "x-updatable": true,
                  "x-scale": 2,
                  "x-precision": 9,
                  "type": "number"
                },
                "valueDesc": {
                  "nullable": true,
                  "default": 0.0,
                  "x-updatable": true,
                  "x-scale": 2,
                  "x-precision": 9,
                  "type": "number"
                },
                "valueFreight": {
                  "nullable": true,
                  "default": 0.0,
                  "x-updatable": true,
                  "x-scale": 2,
                  "x-precision": 9,
                  "type": "number"
                },
                "cfop": {
                  "nullable": true,
                  "x-updatable": true,
                  "x-$ref": "#/components/schemas/nfeCfop",
                  "type": "integer"
                },
                "valueAllTax": {
                  "nullable": true,
                  "default": 0.0,
                  "x-updatable": true,
                  "x-scale": 2,
                  "x-precision": 9,
                  "type": "number"
                },
                "serials": {
                  "nullable": true,
                  "x-updatable": true,
                  "type": "string",
                  "maxLength": 255
                }
              },
              "required": [
                "rufsGroupOwner",
                "request",
                "id",
                "product",
                "quantity",
                "value"
              ]
            },
            "requestService": {
              "x-primaryKeys": [
                "rufsGroupOwner",
                "id"
              ],
              "x-uniqueKeys": {
                "requestServiceRequestServiceKey": [
                  "request",
                  "service"
                ]
              },
              "x-foreignKeys": {
                "requestServiceRufsGroupOwnerEmployedFkey": {
                  "fields": {
                    "employed": "person",
                    "rufsGroupOwner": "rufsGroupOwner"
                  },
                  "tableRef": "employed"
                },
                "requestServiceRufsGroupOwnerRequestFkey": {
                  "fields": {
                    "request": "id",
                    "rufsGroupOwner": "rufsGroupOwner"
                  },
                  "tableRef": "request"
                }
              },
              "type": "object",
              "properties": {
                "rufsGroupOwner": {
                  "x-updatable": true,
                  "x-essential": true,
                  "x-$ref": "#/components/schemas/rufsGroupOwner",
                  "type": "integer"
                },
                "request": {
                  "nullable": true,
                  "x-updatable": true,
                  "x-$ref": "#/components/schemas/request",
                  "type": "integer"
                },
                "id": {
                  "x-updatable": true,
                  "x-identityGeneration": "BY DEFAULT",
                  "x-essential": true,
                  "type": "integer"
                },
                "quantity": {
                  "default": 1.0,
                  "x-updatable": true,
                  "x-essential": true,
                  "x-scale": 3,
                  "x-precision": 9,
                  "type": "number"
                },
                "value": {
                  "default": 0.0,
                  "x-updatable": true,
                  "x-essential": true,
                  "x-scale": 3,
                  "x-precision": 9,
                  "type": "number"
                },
                "valueItem": {
                  "default": 0.0,
                  "x-updatable": true,
                  "x-essential": true,
                  "x-scale": 2,
                  "x-precision": 9,
                  "type": "number"
                },
                "valueDesc": {
                  "default": 0.0,
                  "x-updatable": true,
                  "x-essential": true,
                  "x-scale": 2,
                  "x-precision": 9,
                  "type": "number"
                },
                "valueFrete": {
                  "default": 0.0,
                  "x-updatable": true,
                  "x-essential": true,
                  "x-scale": 2,
                  "x-precision": 9,
                  "type": "number"
                },
                "cfop": {
                  "nullable": true,
                  "x-updatable": true,
                  "x-$ref": "#/components/schemas/nfeCfop",
                  "type": "integer"
                },
                "valueAllTax": {
                  "default": 0.0,
                  "x-updatable": true,
                  "x-essential": true,
                  "x-scale": 2,
                  "x-precision": 9,
                  "type": "number"
                },
                "service": {
                  "x-updatable": true,
                  "x-essential": true,
                  "x-$ref": "#/components/schemas/service",
                  "type": "integer"
                },
                "employed": {
                  "x-updatable": true,
                  "x-essential": true,
                  "x-$ref": "#/components/schemas/employed",
                  "type": "string",
                  "maxLength": 18
                }
              },
              "required": [
                "rufsGroupOwner",
                "id",
                "quantity",
                "value",
                "valueItem",
                "valueDesc",
                "valueFrete",
                "valueAllTax",
                "service",
                "employed"
              ]
            },
            "requestState": {
              "x-primaryKeys": [
                "id"
              ],
              "x-uniqueKeys": {
                "requestStateTypeNameKey": [
                  "type",
                  "name"
                ]
              },
              "x-foreignKeys": {},
              "type": "object",
              "properties": {
                "id": {
                  "x-updatable": true,
                  "x-identityGeneration": "BY DEFAULT",
                  "x-essential": true,
                  "type": "integer"
                },
                "type": {
                  "nullable": true,
                  "x-updatable": true,
                  "x-$ref": "#/components/schemas/requestType",
                  "type": "integer"
                },
                "name": {
                  "x-updatable": true,
                  "x-essential": true,
                  "type": "string",
                  "maxLength": 255
                },
                "stockAction": {
                  "nullable": true,
                  "x-updatable": true,
                  "x-$ref": "#/components/schemas/stockAction",
                  "type": "integer"
                },
                "description": {
                  "nullable": true,
                  "x-updatable": true,
                  "type": "string",
                  "maxLength": 100
                },
                "next": {
                  "nullable": true,
                  "default": 1,
                  "x-updatable": true,
                  "type": "integer"
                },
                "prev": {
                  "nullable": true,
                  "x-updatable": true,
                  "type": "integer"
                }
              },
              "required": [
                "id",
                "name"
              ]
            },
            "requestType": {
              "x-primaryKeys": [
                "id"
              ],
              "x-uniqueKeys": {
                "requestTypeNameKey": [
                  "name"
                ]
              },
              "x-foreignKeys": {},
              "type": "object",
              "properties": {
                "id": {
                  "x-updatable": true,
                  "x-identityGeneration": "BY DEFAULT",
                  "x-essential": true,
                  "type": "integer"
                },
                "description": {
                  "nullable": true,
                  "x-updatable": true,
                  "type": "string",
                  "maxLength": 100
                },
                "name": {
                  "x-updatable": true,
                  "x-essential": true,
                  "type": "string",
                  "maxLength": 255
                }
              },
              "required": [
                "id",
                "name"
              ]
            },
            "rufsGroup": {
              "x-primaryKeys": [
                "id"
              ],
              "properties": {
                "id": {
                  "x-identityGeneration": "BY DEFAULT",
                  "type": "integer"
                },
                "name": {
                  "type": "string"
                }
              }
            },
            "rufsGroupOwner": {
              "x-primaryKeys": [
                "id"
              ],
              "properties": {
                "id": {
                  "x-identityGeneration": "BY DEFAULT",
                  "type": "integer"
                },
                "name": {
                  "type": "string"
                }
              }
            },
            "rufsGroupUser": {
              "x-primaryKeys": [
                "rufsUser",
                "rufsGroup"
              ],
              "x-uniqueKeys": {},
              "properties": {
                "rufsUser": {
                  "x-$ref": "#/components/schemas/rufsUser",
                  "type": "integer"
                },
                "rufsGroup": {
                  "x-$ref": "#/components/schemas/rufsGroup",
                  "type": "integer"
                }
              }
            },
            "rufsUser": {
              "x-primaryKeys": [
                "id"
              ],
              "x-uniqueKeys": {},
              "properties": {
                "id": {
                  "x-identityGeneration": "BY DEFAULT",
                  "type": "integer"
                },
                "rufsGroupOwner": {
                  "x-$ref": "#/components/schemas/rufsGroupOwner",
                  "type": "integer"
                },
                "name": {
                  "type": "string",
                  "maxLength": 32
                },
                "password": {
                  "type": "string"
                },
                "path": {
                  "type": "string"
                },
                "roles": {
                  "type": "array",
                  "items": {
                    "properties": {
                      "path": {
                        "type": "string"
                      },
                      "mask": {
                        "x-flags": "get,post,put,delete",
                        "type": "integer"
                      }
                    }
                  }
                },
                "routes": {
                  "type": "array",
                  "items": {
                    "properties": {
                      "path": {
                        "type": "string"
                      },
                      "controller": {
                        "type": "string"
                      },
                      "templateUrl": {
                        "type": "string"
                      }
                    }
                  }
                },
                "menu": {
                  "type": "array",
                  "items": {
                    "properties": {
                      "group": {
                        "default": "action",
                        "type": "string"
                      },
                      "label": {
                        "type": "string"
                      },
                      "path": {
                        "default": "service/action?filter={}&aggregate={}",
                        "type": "string"
                      }
                    }
                  }
                }
              }
            },
            "service": {
              "x-primaryKeys": [
                "id"
              ],
              "x-uniqueKeys": {
                "serviceNameKey": [
                  "name"
                ]
              },
              "x-foreignKeys": {},
              "type": "object",
              "properties": {
                "id": {
                  "x-updatable": true,
                  "x-identityGeneration": "BY DEFAULT",
                  "x-essential": true,
                  "type": "integer"
                },
                "rufsGroup": {
                  "x-updatable": true,
                  "x-essential": true,
                  "x-$ref": "#/components/schemas/rufsGroup",
                  "type": "integer"
                },
                "unit": {
                  "default": "UN::character varying",
                  "x-updatable": true,
                  "x-essential": true,
                  "type": "string",
                  "maxLength": 255
                },
                "name": {
                  "x-updatable": true,
                  "x-essential": true,
                  "type": "string",
                  "maxLength": 100
                },
                "description": {
                  "nullable": true,
                  "x-updatable": true,
                  "type": "string",
                  "maxLength": 255
                },
                "additionalData": {
                  "nullable": true,
                  "x-updatable": true,
                  "type": "string",
                  "maxLength": 255
                },
                "taxIss": {
                  "default": 0.0,
                  "x-updatable": true,
                  "x-essential": true,
                  "x-scale": 3,
                  "x-precision": 9,
                  "type": "number"
                }
              },
              "required": [
                "id",
                "rufsGroup",
                "unit",
                "name",
                "taxIss"
              ]
            },
            "stock": {
              "x-primaryKeys": [
                "rufsGroupOwner",
                "id"
              ],
              "x-uniqueKeys": {},
              "x-foreignKeys": {},
              "type": "object",
              "properties": {
                "rufsGroupOwner": {
                  "x-updatable": true,
                  "x-essential": true,
                  "x-$ref": "#/components/schemas/rufsGroupOwner",
                  "type": "integer"
                },
                "id": {
                  "x-updatable": true,
                  "x-essential": true,
                  "x-$ref": "#/components/schemas/product",
                  "type": "integer"
                },
                "countIn": {
                  "nullable": true,
                  "default": 0.0,
                  "x-updatable": true,
                  "x-scale": 3,
                  "x-precision": 9,
                  "type": "number"
                },
                "countOut": {
                  "nullable": true,
                  "default": 0.0,
                  "x-updatable": true,
                  "x-scale": 3,
                  "x-precision": 9,
                  "type": "number"
                },
                "estimedIn": {
                  "nullable": true,
                  "x-updatable": true,
                  "x-scale": 3,
                  "x-precision": 9,
                  "type": "number"
                },
                "estimedOut": {
                  "nullable": true,
                  "default": 0.0,
                  "x-updatable": true,
                  "x-scale": 3,
                  "x-precision": 9,
                  "type": "number"
                },
                "estimedValue": {
                  "nullable": true,
                  "default": 0.0,
                  "x-updatable": true,
                  "x-scale": 3,
                  "x-precision": 9,
                  "type": "number"
                },
                "marginSale": {
                  "nullable": true,
                  "default": 50.0,
                  "x-updatable": true,
                  "x-scale": 3,
                  "x-precision": 9,
                  "type": "number"
                },
                "marginWholesale": {
                  "nullable": true,
                  "default": 25.0,
                  "x-updatable": true,
                  "x-scale": 3,
                  "x-precision": 9,
                  "type": "number"
                },
                "reservedIn": {
                  "nullable": true,
                  "default": 0.0,
                  "x-updatable": true,
                  "x-scale": 3,
                  "x-precision": 9,
                  "type": "number"
                },
                "reservedOut": {
                  "nullable": true,
                  "default": 0.0,
                  "x-updatable": true,
                  "x-scale": 3,
                  "x-precision": 9,
                  "type": "number"
                },
                "stockValue": {
                  "nullable": true,
                  "default": 0.0,
                  "x-updatable": true,
                  "x-scale": 3,
                  "x-precision": 9,
                  "type": "number"
                },
                "stockDefault": {
                  "nullable": true,
                  "default": 0.0,
                  "x-updatable": true,
                  "x-scale": 3,
                  "x-precision": 9,
                  "type": "number"
                },
                "stockMinimal": {
                  "nullable": true,
                  "default": 0.0,
                  "x-updatable": true,
                  "x-scale": 3,
                  "x-precision": 9,
                  "type": "number"
                },
                "stockSerials": {
                  "nullable": true,
                  "x-updatable": true,
                  "type": "string",
                  "maxLength": 1024
                },
                "sumValueIn": {
                  "nullable": true,
                  "default": 0.0,
                  "x-updatable": true,
                  "x-scale": 3,
                  "x-precision": 9,
                  "type": "number"
                },
                "sumValueOut": {
                  "nullable": true,
                  "default": 0.0,
                  "x-updatable": true,
                  "x-scale": 3,
                  "x-precision": 9,
                  "type": "number"
                },
                "sumValueStock": {
                  "nullable": true,
                  "default": 0.0,
                  "x-updatable": true,
                  "x-scale": 3,
                  "x-precision": 9,
                  "type": "number"
                },
                "value": {
                  "nullable": true,
                  "default": 0.0,
                  "x-updatable": true,
                  "x-scale": 3,
                  "x-precision": 9,
                  "type": "number"
                },
                "valueWholesale": {
                  "nullable": true,
                  "default": 0.0,
                  "x-updatable": true,
                  "x-scale": 3,
                  "x-precision": 9,
                  "type": "number"
                }
              },
              "required": [
                "rufsGroupOwner",
                "id"
              ]
            },
            "stockAction": {
              "x-primaryKeys": [
                "id"
              ],
              "x-uniqueKeys": {
                "stockActionNameKey": [
                  "name"
                ]
              },
              "x-foreignKeys": {},
              "type": "object",
              "properties": {
                "id": {
                  "x-updatable": true,
                  "x-identityGeneration": "BY DEFAULT",
                  "x-essential": true,
                  "type": "integer"
                },
                "name": {
                  "x-updatable": true,
                  "x-essential": true,
                  "type": "string",
                  "maxLength": 255
                }
              },
              "required": [
                "id",
                "name"
              ]
            }
          }
        },
        "security": [
          {
            "jwt": []
          }
        ],
        "tags": [
          {
            "name": "login"
          },
          {
            "name": "account"
          },
          {
            "name": "bacenCountry"
          },
          {
            "name": "barcode"
          },
          {
            "name": "camexNcm"
          },
          {
            "name": "confazCest"
          },
          {
            "name": "employed"
          },
          {
            "name": "ibgeCity"
          },
          {
            "name": "ibgeCnae"
          },
          {
            "name": "ibgeUf"
          },
          {
            "name": "nfeCfop"
          },
          {
            "name": "nfeStCofins"
          },
          {
            "name": "nfeStCsosn"
          },
          {
            "name": "nfeStIcms"
          },
          {
            "name": "nfeStIcmsDesoneracao"
          },
          {
            "name": "nfeStIcmsModalidadeBc"
          },
          {
            "name": "nfeStIcmsModalidadeSt"
          },
          {
            "name": "nfeStIcmsOrigem"
          },
          {
            "name": "nfeStIpi"
          },
          {
            "name": "nfeStIpiEnquadramento"
          },
          {
            "name": "nfeStIpiOperacao"
          },
          {
            "name": "nfeStPis"
          },
          {
            "name": "nfeTaxGroup"
          },
          {
            "name": "nfseCodService"
          },
          {
            "name": "paymentType"
          },
          {
            "name": "person"
          },
          {
            "name": "product"
          },
          {
            "name": "request"
          },
          {
            "name": "requestFreight"
          },
          {
            "name": "requestNfe"
          },
          {
            "name": "requestPayment"
          },
          {
            "name": "requestProduct"
          },
          {
            "name": "requestService"
          },
          {
            "name": "requestState"
          },
          {
            "name": "requestType"
          },
          {
            "name": "rufsGroup"
          },
          {
            "name": "rufsGroupOwner"
          },
          {
            "name": "rufsGroupUser"
          },
          {
            "name": "rufsUser"
          },
          {
            "name": "service"
          },
          {
            "name": "stock"
          },
          {
            "name": "stockAction"
          }
        ]
      }
"##;
}
