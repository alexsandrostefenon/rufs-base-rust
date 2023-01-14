use tide::Error;

use crate::rufs_micro_service::LoginResponse;

use openapiv3::OpenAPI;

#[derive(serde::Deserialize, Default)]
pub struct LoginRequest {
    pub user: String,
    pub password: String,
}

pub trait IMicroServiceServer {
    fn init(&mut self) -> Result<(), Error>;
    fn authenticate_user(&self, user_name: String, user_password: String, remote_addr: String) -> Result<LoginResponse, Error>;
    //fn set_imss(&mut self, imss :MicroServiceServerType) where Self: Sized;
    //fn load_open_api(&self) -> Result<(), tide::Error>;
    //fn listen(&self) -> async_std::io::Result<()>;
    //fn shutdown(&self) -> Result<(), tide::Error>;
    //fn on_request(&self, req : tide::Request<()>) -> tide::Response<>;
    //fn OnWsMessageFromClient(connection : websocketConn, tokenString : String);
}

pub struct MicroServiceServer {
    pub app_name: String,
    //protocol : String,
    pub port: u16,
    //addr : String,
    pub api_path: String,
    //security : String,
    pub request_body_content_type: String,
    pub serve_static_paths: Vec<std::path::PathBuf>,
    //openapi_file_name : String,
    pub openapi: OpenAPI,
    //wsServerConnections    : HashMap<String, websocketConn>,
    //http_server             : Option<Arc<tide::Server<MicroServiceServer>>>,
    //imss : MicroServiceServerType
}

impl Default for MicroServiceServer {
    fn default() -> Self {
        Self {
            port: 8080,
            api_path: "rest".to_string(),
            serve_static_paths: Default::default(),
            openapi: Default::default(),
            app_name: "base".to_string(),
            request_body_content_type: "application/json".to_string(),
        }
    }
}

impl IMicroServiceServer for MicroServiceServer {
    fn init(&mut self) -> Result<(), Error> {
        Ok(())
    }

    fn authenticate_user(&self, user_name: String, user_password: String, remote_addr: String) -> Result<LoginResponse, Error> {
        println!("[MicroServiceServer.authenticate_user({}, {}, {})]", user_name, user_password, remote_addr);
        todo!()
    }
}
/*
func (mss *MicroServiceServer) OnRequest(req *http.Request) Response {
    log.Printf("[MicroServiceServer.OnRequest] : %s", req.URL.Path)
    return ResponseOk("OnRequest")
}

func (mss *MicroServiceServer) Listen() error {
    mss.wsServerConnections = make(map[string]*websocket.Conn)
    serveStaticPaths := path.Join(path.Dir(reflect.TypeOf(mss).PkgPath()), "webapp")

    if mss.ServeStaticPaths == "" {
        mss.ServeStaticPaths = serveStaticPaths
    } else {
        mss.ServeStaticPaths += "," + serveStaticPaths
    }

    if mss.port == 0 {
        mss.port = 8080
    }

    if mss.apiPath == "" {
        mss.apiPath = "rest"
    }

    if mss.Imss == nil {
        mss.Imss = mss
    }

    mss.httpServer = &http.Server{Addr: fmt.Sprintf("%s:%d", mss.addr, mss.port)}

    http.HandleFunc("/", func(res http.ResponseWriter, req *http.Request) {
        found := false
        name := req.RequestURI

        if strings.HasSuffix(name, "/") {
            name = name + "index.html"
        }

        for _, folder := range strings.Split(mss.ServeStaticPaths, ",") {
            absFolder, _ := filepath.Abs(folder)
            fileName := path.Join(absFolder, name)

            if fileInfo, err := os.Stat(fileName); err == nil && !fileInfo.IsDir() {
                http.ServeFile(res, req, fileName)
                found = true
                log.Printf("[MicroServiceServer.Init] served file : %s : %s : %s", folder, req.RequestURI, fileName)
                break
            }
        }

        if !found {
            log.Printf("[MicroServiceServer.HandleFunc] : searching file %s is not result", req.RequestURI)
            res.WriteHeader(http.StatusBadRequest)
            res.Write([]byte{})
        }
    })

    http.HandleFunc("/"+mss.apiPath+"/", func(res http.ResponseWriter, req *http.Request) {
        buf, _ := ioutil.ReadAll(req.Body)
        rdr1 := ioutil.NopCloser(bytes.NewBuffer(buf))
        rdr2 := ioutil.NopCloser(bytes.NewBuffer(buf))
        log.Printf("authorization='%s';", req.Header.Get("Authorization"))
        log.Printf("curl -X '%s' %s -d '%s' -H \"Authorization: $authorization\";", req.Method, req.RequestURI, rdr1)
        req.Body = rdr2
        res.Header().Set("Access-Control-Allow-Origin", "*")
        res.Header().Set("Access-Control-Allow-Methods", "GET, PUT, OPTIONS, POST, DELETE")
        res.Header().Set("Access-Control-Allow-Headers", req.Header.Get("Access-Control-Request-Headers"))

        if req.Method == http.MethodOptions {
            fmt.Fprint(res, "Ok")
            return
        }

        ret := mss.Imss.OnRequest(req)
        res.Header().Set("Content-Type", ret.ContentType)
        //log.Printf("[HandleFunc] : ret.Body = %s", string(ret.Body))
        res.WriteHeader(ret.StatusCode)
        res.Write(ret.Body)
    })

    upgrader := websocket.Upgrader{}
    log.Printf("[MicroServiceServer.Init] : websocket")

    http.HandleFunc("/websocket", func(w http.ResponseWriter, req *http.Request) {
        log.Printf("[MicroServiceServer.HandleFunc] : received websocket request %s from %s", req.RequestURI, req.RemoteAddr)
        connection, err := upgrader.Upgrade(w, req, nil)

        if err != nil {
            log.Print("upgrade:", err)
            return
        }

        defer connection.Close()

        for {
            messageType, message, err := connection.ReadMessage()

            if err != nil {
                log.Println("read:", err)
                break
            }

            if messageType != 1 {
                log.Println("Invalid Message Type:", messageType)
                break
            }

            mss.Imss.OnWsMessageFromClient(connection, string(message))
        }
    })

    log.Print("[MicroServiceServer.Listen]")
    return mss.httpServer.ListenAndServe()
}

func (mss *MicroServiceServer) LoadOpenApi() error {
    if mss.openapiFileName == "" {
        mss.openapiFileName = fmt.Sprintf("openapi-%s.json", mss.appName)
    }

    if mss.security == "" {
        mss.security = "jwt"
    }

    if mss.openapi == nil {
        mss.openapi = &OpenApi{}
    }

    if data, err := ioutil.ReadFile(mss.openapiFileName); err == nil {
        if err = json.Unmarshal(data, mss.openapi); err != nil {
            UtilsShowJsonUnmarshalError(string(data), err)
            log.Fatalf("[MicroServiceServer.LoadOpenApi] : %s", err)
            OpenApiCreate(mss.openapi, mss.security)
        }
    } else {
        OpenApiCreate(mss.openapi, mss.security)
    }

    if len(mss.openapi.Servers) == 0 {
        mss.openapi.Servers = append(mss.openapi.Servers, &ServerObject{Url: fmt.Sprintf("%s://localhost:%d/%s", mss.protocol, mss.port, mss.apiPath)})
        mss.openapi.Servers = append(mss.openapi.Servers, &ServerObject{Url: fmt.Sprintf("%s://localhost:%d/%s/%s", mss.protocol, (mss.port/10)*10, mss.appName, mss.apiPath)})
    }

    mss.openapi.convertStandartToRufs()
    return nil
}

func (mss *MicroServiceServer) StoreOpenApi(fileName string) (err error) {
    if fileName == "" {
        fileName = fmt.Sprintf("openapi-%s.json", mss.appName)
    }

    if data, err := json.MarshalIndent(mss.openapi, "", "\t"); err != nil {
        log.Fatalf("[FileDbAdapterStore] : failt to marshal list before wrinting file %s : %s", fileName, err)
    } else if err = ioutil.WriteFile(fileName, data, fs.ModePerm); err != nil {
        log.Fatalf("[FileDbAdapterStore] : failt to write file %s : %s", fileName, err)
    }

    return err
}

func (mss *MicroServiceServer) OnWsMessageFromClient(connection *websocket.Conn, tokenString string) {
}

func (mss *MicroServiceServer) Shutdown() {
    mss.httpServer.Shutdown(context.Background())
}
 */
