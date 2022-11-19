pub mod db_adapter_file;

use std::collections::HashMap;

use crate::db_adapter_file::OpenApi;
use crate::db_adapter_file::DbAdapterFile;
use tide::Error;

/*
trait IMicroServiceServer {
	//fn load_open_api(&self) -> Result<(), tide::Error>;
	fn listen(&self) -> async_std::io::Result<()>;
	//fn shutdown(&self) -> Result<(), tide::Error>;
	//fn on_request(&self, req : tide::Request<()>) -> tide::Response<>;
	//fn OnWsMessageFromClient(connection : websocketConn, tokenString : String);
}
*/
#[derive(Debug)]
struct User {
//    name: String,
}

#[derive(Clone, Default, Debug)]
struct MicroServiceServer {
	//app_name : String,
	//protocol : String,
	port : u16,
	//addr : String,
	api_path : String,
	//security : String,
	//request_body_content_type : String,
	serve_static_paths : Vec<std::path::PathBuf>,
	//openapi_file_name : String,
	openapi                : Option<OpenApi>,
	//wsServerConnections    : HashMap<String, websocketConn>,
	http_server             : Option<Box<tide::Server<MicroServiceServer>>>,
	//imss                   : Option<&'a dyn IMicroServiceServer> 
}

#[derive(serde::Deserialize)]
#[derive(Clone, Default, Debug)]
#[allow(dead_code)]
struct LoginRequest {user: String, password : String}
//impl IMicroServiceServer for MicroServiceServer<'_> {
impl MicroServiceServer {
	/*
	fn on_request(&self, req : tide::Request<()>) -> tide::Response<> {
		//log.Printf("[MicroServiceServer.OnRequest] : %s", req.URL.Path);
		return tide::Response::builder(200).content_type(tide::http::mime::JSON).body("OnRequest").build()
	}
*/
	async fn init(&mut self) -> async_std::io::Result<()> {
		//self.wsServerConnections = make(map[string]*websocket.Conn);
		if self.port == 0 {
			self.port = 8080;
		}

		if self.api_path == "" {
			self.api_path = "rest".to_string();
		}
/*
		if Option::is_none(&self.imss) {
			self.imss = Some(self);
		}

		if self.http_server.is_none() {
			self.http_server = Option::Some(tide::with_state(MicroServiceServer::default()));
		}
*/

		Ok(())
	}
/*
	fn load_open_api(&self) -> Result<(), tide::Error> {
		if self.openapi_file_name == "" {
			self.openapi_file_name = fmt.Sprintf("openapi-%s.json", self.app_name)
		}

		if self.security == "" {
			self.security = "jwt"
		}

		if self.openapi == nil {
			self.openapi = OpenApi{}
		}

		if let data = ioutil.ReadFile(self.openapi_file_name) {
			if let err = json.Unmarshal(data, self.openapi) && err != nil {
				UtilsShowJsonUnmarshalError(string(data), err);
				log.Fatalf("[MicroServiceServer.LoadOpenApi] : %s", err);
				OpenApiCreate(self.openapi, self.security);
			}
		} else {
			OpenApiCreate(self.openapi, self.security);
		}

		if self.openapi.Servers.len == 0 {
			self.openapi.Servers = append(self.openapi.Servers, &ServerObject{Url: fmt.Sprintf("%s://localhost:%d/%s", self.protocol, self.port, self.api_path)});
			self.openapi.Servers = append(self.openapi.Servers, &ServerObject{Url: fmt.Sprintf("%s://localhost:%d/%s/%s", self.protocol, (self.port/10)*10, self.app_name, self.api_path)});
		}

		self.openapi.convertStandartToRufs();
		return nil
	}

	fn store_open_api(&self, file_name : String) -> Result<(), Error> {
		if file_name == "" {
			file_name = fmt.Sprintf("openapi-%s.json", self.app_name)
		}

		let data = json.MarshalIndent(self.openapi, "", "\t");
		ioutil.WriteFile(file_name, data, fs.ModePerm);
		return err
	}

	fn on_ws_message_from_client(&self, connection : websocketConn, tokenString : String) {
	}

	fn shutdown(&self) {
		self.http_server.Shutdown(context.Background())
	}
*/
}
/*
struct RufsGroupOwner {
	id   : u64,
	name : String
}

struct Route  {
	path        : String,
	controller  :String,
	template_url :String
}

struct MenuItem  {
	menu  string `json:"menu"`
	Label string `json:"label"`
	Path  string `json:"path"`
}

struct Role  {
	Path string `json:"path"`
	Mask int    `json:"mask"`
}

struct RufsUserProteced  {
	Id             int    `json:"id"`
	Name           string `json:"name"`
	RufsGroupOwner int    `json:"rufsGroupOwner"`
	Groups         []int  `json:"groups"`
	Roles          []Role `json:"roles"`
}

struct RufsUserPublic  {
	Routes []Route             `json:"routes"`
	Menu   map[string]MenuItem `json:"menu"`
	Path   string              `json:"path"`
}

struct RufsUser  {
	RufsUserProteced
	RufsUserPublic
	FullName string `json:"fullName"`
	Password string `json:"password"`
}

struct TokenPayload  {
	RufsUserProteced
	Ip string `json:"ip"`
}
*/
#[derive(Clone, Default, Debug)]
struct LoginResponse {
//	TokenPayload
//	RufsUserPublic
	//jwt_header :String,
	//title     :String,
	openapi                : Option<OpenApi>,
}
/*
struct RufsClaims  {
	*jwt.StandardClaims
	TokenPayload
}
*/
/*
type EntityManager interface {
	Connect() error
	Find(tableName string, fields map[string]any, orderBy []string) ([]map[string]any, error)
	FindOne(tableName string, fields map[string]any) (map[string]any, error)
	Insert(tableName string, obj map[string]any) (map[string]any, error)
	Update(tableName string, key map[string]any, obj map[string]any) (map[string]any, error)
	DeleteOne(tableName string, key map[string]any) error
	UpdateOpenApi(openapi *OpenApi, options FillOpenApiOptions) error
	CreateTable(name string, schema *Schema) (sql.Result, error)
}

type IRufsMicroService interface {
	IMicroServiceServer
	LoadFileTables() error
}
*/
	
#[derive(Clone, Default, Debug)]
struct RufsMicroService  {
	micro_service_server : MicroServiceServer,
	/*
	dbConfig                  *DbConfig
	checkRufsTables           bool
	migrationPath             string
	Irms                      IRufsMicroService
	wsServerConnectionsTokens map[string]*RufsClaims
	entityManager EntityManager
	*/
	db_adapter_file :DbAdapterFile
}

fn authenticate_user(user_name :String, user_password :String, remote_addr :String) -> Result<LoginResponse, tide::Error> {
	let mut db_file = db_adapter_file::DbAdapterFile::default();
	db_file.openapi = OpenApi::default();
/*
	let entityManager = if rms.fileDbAdapter.fileTables["rufsUser"].exists {
		entityManager = rms.fileDbAdapter
	} else {
		entityManager = rms.entityManager
	}
	time.Sleep(100 * time.Millisecond)
	user := &RufsUser{}

	if userMap, err := entityManager.FindOne("rufsUser", map[string]any{"name": userName}); err == nil {
		data, _ := json.Marshal(userMap)

		if err := json.Unmarshal(data, user); err != nil {
			UtilsShowJsonUnmarshalError(string(data), err)
			return nil, err
		}
	} else {
		return nil, fmt.Errorf("[RufsMicroService.authenticateUser] internal error : %s", err)
	}

	if len(user.Password) > 0 && user.Password != userPassword {
		return nil, errors.New("Don't match user and password.")
	}

	loginResponse := &LoginResponse{TokenPayload: TokenPayload{Ip: remoteAddr, RufsUserProteced: RufsUserProteced{Name: userName}}}
	loginResponse.Title = user.Name
	loginResponse.Id = user.Id
	loginResponse.RufsGroupOwner = user.RufsGroupOwner
	loginResponse.Roles = user.Roles
	loginResponse.Routes = user.Routes
	loginResponse.Path = user.Path
	loginResponse.Menu = user.Menu

	if loginResponse.RufsGroupOwner > 0 {
		/*
			const item = OpenApi.getPrimaryKeyForeign(this.openapi, "rufsUser", "rufsGroupOwner", user)
			return entityManager.findOne("rufsGroupOwner", item.primaryKey).then(rufsGroupOwner => {
				if (rufsGroupOwner != null) loginResponse.title = rufsGroupOwner.name + " - " + userName;
				return loginResponse
			})
		*/
	}

	if list, err := entityManager.Find("rufsGroupUser", map[string]any{"rufsUser": loginResponse.Id}, []string{}); err == nil {
		for _, item := range list {
			loginResponse.Groups = append(loginResponse.Groups, int(item["rufsGroup"].(int64)))
		}
	} else {
		return nil, fmt.Errorf("[RufsMicroService.authenticateUser] internal error : %s", err)
	}
*/
	let login_response = LoginResponse::default();

	println!("authenticate_user({}, {}, {})", user_name, user_password, remote_addr);

	Ok(login_response)
}

fn request_filter<'a>(mut request: tide::Request<MicroServiceServer>) -> std::pin::Pin<Box<dyn std::future::Future<Output = tide::Result> + Send + 'a>> {
	Box::pin(async move {
		let found = false;

		let acess_control_request_headers = match request.header("Access-Control-Request-Headers") {
			Some(value) => value.to_string(),
			None => "".to_string()
		};

		let method = request.method().clone();

		let mut response = if !found {
			tide::Response::new(tide::StatusCode::NotFound)
		} else {
			tide::Response::new(tide::StatusCode::NotFound)
//				next.run(request).await
		};

		let path = request.url().path();
		let endpoint_login = format!("/{}/login", request.state().api_path);

		if path.starts_with(&endpoint_login) {
			let login_request = request.body_json::<LoginRequest>().await?;

			if login_request.user.is_empty() || login_request.password.is_empty() {
				println!("Login request is empty");
			}

			let mut login_response = authenticate_user(login_request.user.clone(),login_request.password.clone(), request.remote().unwrap().to_string().clone()).expect("authenticate_user");

			if login_request.user == "admin".to_string() {
				login_response.openapi = request.state().openapi.clone();
			} else {
				//loginResponse.Openapi = rms.openapi.copy(loginResponse.Roles)
				login_response.openapi = request.state().openapi.clone();
			}

/*
			token := jwt.New(jwt.SigningMethodHS256)
			token.Claims = &RufsClaims{&jwt.StandardClaims{ExpiresAt: time.Now().Add(time.Minute * 60 * 8).Unix()}, loginResponse.TokenPayload}
			jwtSecret := os.Getenv("RUFS_JWT_SECRET")

			if jwtSecret == "" {
				jwtSecret = "123456"
			}

			loginResponse.JwtHeader, err = token.SignedString([]byte(jwtSecret))
			return ResponseOk(loginResponse)
		*/
	//} else {
			/*
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
			*/
		}

		response.insert_header("Access-Control-Allow-Origin", "*");
		response.insert_header("Access-Control-Allow-Methods", "GET, PUT, OPTIONS, POST, DELETE");

		if acess_control_request_headers.is_empty() == false {
			response.insert_header("Access-Control-Allow-Headers", acess_control_request_headers);
		}

		if method == tide::http::Method::Options {
			return Ok(response);
		}

		//ret = self.imss.OnRequest(req);
		//response.insert_header("Content-Type", ret.ContentType);

		Ok(response)
	})
}

fn serve_dir<'a>(request: tide::Request<MicroServiceServer>, next: tide::Next<'a, MicroServiceServer>) -> std::pin::Pin<Box<dyn std::future::Future<Output = tide::Result> + Send + 'a>> {
	Box::pin(async {
		let path = request.url().path()[1..].to_string().clone();

		let name = if path.ends_with("/") || path.is_empty() {
			path.clone() + &"index.html".to_string()
		} else {
			path.clone()
		};

		let current_dir = std::env::current_dir().unwrap();

		for folder in &request.state().serve_static_paths {
			let file = current_dir.join(folder).join(&name);

			if file.exists() {
				match tide::Body::from_file(&file).await {
					Ok(body) => return Ok(tide::Response::builder(tide::StatusCode::Ok).body(body).build()),
					Err(e)=> return Err(e.into())
				}
			} else {
				println!("[MicroServiceServer.listen().serve_dir()] current_dir = {}, folder = {}, name = {} don't found.", current_dir.to_str().unwrap(), folder.to_str().unwrap(), path);
			}
		}
	
		//Ok(tide::Response::new(tide::StatusCode::NotFound))
		Ok(next.run(request).await)
	})
}

#[async_std::main]
async fn main() -> tide::Result<()> {
	let mut rufs = RufsMicroService::default();
	rufs.micro_service_server.port = 8080;
	rufs.micro_service_server.api_path = "rest".to_string();
	rufs.micro_service_server.serve_static_paths = vec![std::path::Path::new("../rufs-nfe-es6/webapp").to_path_buf(), std::path::Path::new("../rufs-crud-es6/webapp").to_path_buf(), std::path::Path::new("../rufs-base-es6/webapp").to_path_buf()];
/*    let mut server = MicroServiceServer{
		//app_name: "".to_string(),
		//protocol: "".into(),
		port: 8080,
		//addr: "127.0.0.1".to_string(),
		api_path: "api".to_string(),
		//security: "".into(),
		//request_body_content_type: "".into(),
		serve_static_paths: paths,
		//openapi_file_name: "".into(),
//		http_server: Option::None
		//imss: Option::None
	};*/
	rufs.micro_service_server.http_server = Option::Some(Box::new(tide::with_state(rufs.micro_service_server.clone())));
	rufs.micro_service_server.init().await?;
	let rest_path = format!("/{}/*", rufs.micro_service_server.api_path);
	println!("api path : {}", rest_path);
	rufs.micro_service_server.http_server.as_mut().unwrap().at(&rest_path).all(request_filter);
		
	rufs.micro_service_server.http_server.as_mut().unwrap().at("/websocket").with(tide_websockets::WebSocket::new(|_request, mut stream| async move {
		while let Some(Ok(tide_websockets::Message::Text(input))) = async_std::stream::StreamExt::next(&mut stream).await {
			let output: String = input.chars().rev().collect();
			//self.imss.OnWsMessageFromClient(connection, string(message));

			stream
				.send_string(format!("{} | {}", &input, &output))
				.await?;
		}

		Ok(())
	}));

	rufs.micro_service_server.http_server.as_mut().unwrap().with(serve_dir);
	rufs.load_file_tables()?;
	rufs.micro_service_server.http_server.unwrap().listen("127.0.0.1:8080").await?;
    Ok(())
}
/*
func (rms *RufsMicroService) OnWsMessageFromClient(connection *websocket.Conn, tokenString string) {
	rms.MicroServiceServer.OnWsMessageFromClient(connection, tokenString)

	token, err := jwt.ParseWithClaims(tokenString, &RufsClaims{}, func(token *jwt.Token) (interface{}, error) {
		// Don't forget to validate the alg is what you expect:
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
impl RufsMicroService {

fn load_file_tables(&mut self) -> Result<(), Error> {
	fn load_table(rms :&mut RufsMicroService, name :String, default_rows :&serde_json::Value) -> Result<(), Error> {
		if rms.db_adapter_file.tables.contains_key(&name) {
			return Ok(());
		}

		rms.db_adapter_file.load(name, default_rows)
	}

	if self.micro_service_server.openapi.is_none() {
/* 		if err := rms.Imss.LoadOpenApi(); err != nil {
			return err
		}
 */	}

	self.db_adapter_file = DbAdapterFile{openapi: self.micro_service_server.openapi.as_ref().unwrap().clone(), tables: HashMap::default()};
	//RequestFilterUpdateRufsServices(rms.fileDbAdapter, rms.openapi)
	let empty_list = serde_json::Value::default();
	load_table(self, "rufsGroup".to_string(), &empty_list)?;
	load_table(self, "rufsGroupUser".to_string(), &empty_list)?;
	let item : serde_json::Value = serde_json::from_str(DEFAULT_GROUP_OWNER_ADMIN_STR).unwrap();
	let list = serde_json::json!([item]);
	load_table(self, "rufsGroupOwner".to_string(), &list)?;
	let item : serde_json::Value = serde_json::from_str(DEFAULT_USER_ADMIN_STR).unwrap();
	let list = serde_json::json!([item]);
	load_table(self, "rufsUser".to_string(), &list)?;
	Ok(())
}
	
}
/*
func UtilsShowJsonUnmarshalError(str string, err error) {
	lineAndCharacter := func(input string, offset int) (line int, character int, err error) {
		lf := rune(0x0A)

		if offset > len(input) || offset < 0 {
			return 0, 0, fmt.Errorf("Couldn't find offset %d within the input.", offset)
		}

		// Humans tend to count from 1.
		line = 1

		for i, b := range input {
			if b == lf {
				line++
				character = 0
			}
			character++
			if i == offset {
				break
			}
		}

		return line, character, nil
	}

	if jsonError, ok := err.(*json.SyntaxError); ok {
		line, character, lcErr := lineAndCharacter(str, int(jsonError.Offset))
		fmt.Fprintf(os.Stderr, "Cannot parse JSON schema due to a syntax error at line %d, character %d: %v\n", line, character, jsonError.Error())

		if lcErr != nil {
			fmt.Fprintf(os.Stderr, "Couldn't find the line and character position of the error due to error %v\n", lcErr)
		}
	} else if jsonError, ok := err.(*json.InvalidUnmarshalError); ok {
		fmt.Fprintf(os.Stderr, "Cannot parse JSON schema due to a InvalidUnmarshalError : %v\n", jsonError.Error())
	}
}

func (rms *RufsMicroService) Listen() error {
	createRufsTables := func(openapiRufs *OpenApi) error {
		if !rms.checkRufsTables {
			return nil
		}

		for _, name := range []string{"rufsGroupOwner", "rufsUser", "rufsGroup", "rufsGroupUser"} {
			if _, ok := rms.openapi.Components.Schemas[name]; !ok {
				schema := openapiRufs.Components.Schemas[name]

				if _, err := rms.entityManager.CreateTable(name, schema); err != nil {
					return err
				}
			}
		}

		if response, _ := rms.entityManager.FindOne("rufsGroupOwner", map[string]any{"name": "ADMIN"}); response == nil {
			if _, err := rms.entityManager.Insert("rufsGroupOwner", defaultGroupOwnerAdmin); err != nil {
				return err
			}
		}

		if response, _ := rms.entityManager.FindOne("rufsUser", map[string]any{"name": "admin"}); response == nil {
			if _, err := rms.entityManager.Insert("rufsUser", defaultUserAdmin); err != nil {
				return err
			}
		}

		return nil
	}

	execMigrations := func() error {
		getVersion := func(name string) (int, error) {
			regExp := regexp.MustCompile(`(\d{1,3})\.(\d{1,3})\.(\d{1,3})`)
			regExpResult := regExp.FindStringSubmatch(name)

			if len(regExpResult) != 4 {
				return 0, fmt.Errorf(`Missing valid version in name %s`, name)
			}

			version, _ := strconv.Atoi(fmt.Sprintf(`%03s%03s%03s`, regExpResult[1], regExpResult[2], regExpResult[3]))
			return version, nil
		}

		migrate := func(fileName string) error {
			file, err := os.Open(filepath.Join(rms.migrationPath, fileName)) //`${this.config.migrationPath}/${fileName}`, "utf8"

			if err != nil {
				return err
			}

			defer file.Close()
			fileData, err := ioutil.ReadAll(file)

			if err != nil {
				return err
			}

			text := string(fileData)
			list := strings.Split(text, "--split")

			for _, sql := range list {
				_, err := rms.entityManager.(*DbClientSql).client.Exec(sql)

				if err != nil {
					return err
				}
			}

			newVersion, err := getVersion(fileName)

			if err != nil {
				return err
			}

			rms.openapi.Info.Version = fmt.Sprintf(`%d.%d.%d`, ((newVersion/1000)/1000)%1000, (newVersion/1000)%1000, newVersion%1000)
			return err
		}

		if rms.migrationPath == "" {
			rms.migrationPath = fmt.Sprintf(`./rufs-%s-es6/sql`, rms.appName)
		}

		if _, err := os.Stat(rms.migrationPath); errors.Is(err, os.ErrNotExist) {
			return nil
		}

		oldVersion, err := getVersion(rms.openapi.Info.Version)

		if err != nil {
			return err
		}

		files, err := ioutil.ReadDir(rms.migrationPath)

		if err != nil {
			return err
		}

		list := []string{}

		for _, fileInfo := range files {
			version, err := getVersion(fileInfo.Name())

			if err != nil {
				return err
			}

			if version > oldVersion {
				list = append(list, fileInfo.Name())
			}
		}

		sort.Slice(list, func(i, j int) bool {
			versionI, _ := getVersion(list[i])
			versionJ, _ := getVersion(list[j])
			return versionI < versionJ
		})

		for _, fileName := range list {
			if err := migrate(fileName); err != nil {
				return err
			}
		}

		rms.entityManager.UpdateOpenApi(rms.openapi, FillOpenApiOptions{requestBodyContentType: rms.requestBodyContentType})
		return rms.StoreOpenApi("")
	}

	if err := json.Unmarshal([]byte(defaultGroupOwnerAdminStr), &defaultGroupOwnerAdmin); err != nil {
		UtilsShowJsonUnmarshalError(defaultGroupOwnerAdminStr, err)
		return err
	}

	if err := json.Unmarshal([]byte(defaultUserAdminStr), &defaultUserAdmin); err != nil {
		UtilsShowJsonUnmarshalError(defaultUserAdminStr, err)
		return err
	}

	rms.wsServerConnectionsTokens = make(map[string]*RufsClaims)

	if rms.appName == "" {
		rms.appName = "base"
	}

	if rms.Irms == nil {
		rms.Irms = rms
	}

	if rms.Imss == nil {
		rms.Imss = rms
	}

	openapiRufs := &OpenApi{}

	if err := json.Unmarshal([]byte(rufsMicroServiceOpenApiStr), openapiRufs); err != nil {
		UtilsShowJsonUnmarshalError(rufsMicroServiceOpenApiStr, err)
		return err
	}

	if rms.openapi == nil {
		if err := rms.Imss.LoadOpenApi(); err != nil {
			return err
		}
	}

	rms.entityManager = &DbClientSql{dbConfig: rms.dbConfig}

	//console.log(`[${rms.constructor.name}] starting ${rms.config.appName}...`);
	if err := rms.entityManager.Connect(); err != nil {
		return err
	}

	if err := rms.entityManager.UpdateOpenApi(rms.openapi, FillOpenApiOptions{requestBodyContentType: rms.requestBodyContentType}); err != nil {
		return err
	}

	if err := createRufsTables(openapiRufs); err != nil {
		return err
	}

	rms.openapi.FillOpenApi(FillOpenApiOptions{schemas: openapiRufs.Components.Schemas, requestBodyContentType: rms.requestBodyContentType, security: map[string][]string{"jwt": {}}})

	if err := execMigrations(); err != nil {
		return err
	}

	rms.Irms.LoadFileTables()

	if err := RequestFilterUpdateRufsServices(rms.entityManager, rms.openapi); err != nil {
		return err
	}

	if err := rms.MicroServiceServer.Listen(); err != nil {
		return err
	}

	return nil
}

var rufsMicroServiceOpenApiStr string = `{
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
}
*/
const DEFAULT_GROUP_OWNER_ADMIN_STR : &str = r#"{"name": "admin"}"#;
//var defaultGroupOwnerAdmin map[string]any = map[string]any{}

const DEFAULT_USER_ADMIN_STR : &str = r#"{
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
				"controller": "OpenApiOperationObjectController",
				"path": "/app/rufs_service/:action"
			},
			{
				"controller": "UserController",
				"path": "/app/rufs_user/:action"
			}
		]
	}"#;
//var defaultUserAdmin map[string]any = map[string]any{}
