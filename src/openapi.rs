use std::{collections::HashMap, io::Error};

use convert_case::{Case, Casing};
use indexmap::IndexMap;
use openapiv3::*;
use serde::{Serialize, Deserialize};
use serde_json::{Value, json};

// (service, (service.field|foreign_table_name), service.obj) => [{name: constraint_name, table: foreign_table_name, foreignKey: {}}]
pub struct PrimaryKeyForeign {
    //table:       String,
    pub primary_key:  Value,
    pub valid:       bool,
    //is_unique_key: bool
}

pub struct ForeignKeyDescription {
    //table_ref: String,
    fields_ref: Value,
    //is_unique_key: bool
}

pub trait RufsOpenAPI {
    fn get_schema_name_from_ref(reference: &str) -> String;
    fn create(&mut self, security: &str);
    fn copy_value(&self, schema: &Schema, field_name:&String, field: &Schema, value :&Value) -> Result<Value, Error>;
    fn get_value_from_schema<'a>(&'a self, schema :&Schema, property_name :&str, obj: &'a Value) -> Option<&Value>;
    fn copy_fields(&self, schema: &Schema, data_in: &Value, ignorenil: bool, ignore_hiden: bool, only_primary_keys: bool) -> Result<Value, Error>;
    fn fill(&mut self, options: &mut FillOpenAPIOptions) -> Result<(), Error>;
    fn get_schema_from_schemas(&self, reference :&str) -> Option<&Schema>;
    fn get_schema_from_request_bodies(&self, schema_name: &str) -> Option<&Schema>;
    fn get_schema_from_responses(&self, schema_name: &str) -> Option<&Schema>;
    fn get_schema_from_parameters(&self, path: &str, method: &str) -> Result<&Schema, Error>;
    fn get_schema(&self, path :&str, method :&str, typ :&str) -> Result<&Schema, Error>;
    fn get_schema_from_ref(&self, reference: &str) -> Result<&Schema, Error>;
    fn get_path_params(&self, uri: &str, params: &Value) -> Result<String, Error>;
    fn get_schema_name(&self, path: &str, method: &str) -> Result<String, Error>;
    fn get_properties_from_schema_name<'a>(&'a self, schema_name :&str) -> Option<&'a IndexMap<String, ReferenceOr<Box<Schema>>>>;
    fn get_properties_from_schema<'a>(&'a self, schema :&'a Schema) -> Option<&'a IndexMap<String, ReferenceOr<Box<Schema>>>>;
    fn get_property_from_schema<'a>(&'a self, schema :&'a Schema, property_name :&'a str) -> Option<&'a Schema>;
    fn get_property_from_schemas<'a>(&'a self, schema_name: &str, property_name :&'a str) -> Option<&Schema>;
    fn get_property_from_request_bodies<'a>(&'a self, schema_name :&str, property_name :&'a str) -> Option<&Schema>;
    fn get_property<'a>(&'a self, schema_name :&str, property_name :&'a str) -> Option<&Schema>;
    //fn get_properties_with_ref(&self, schema_name :&str, reference :&str) -> Vec<PropertiesWithRef>;
    fn get_foreign_key_description(&self, schema :&str, field_name: &str) -> Result<Option<ForeignKeyDescription>, Error>;
    fn get_primary_key_foreign(&self, schema_name :&str, field_name :&str, obj :&Value) -> Result<Option<PrimaryKeyForeign>, Error>;
}

#[derive(Debug)]
pub struct FillOpenAPIOptions {
    force_generate_schemas: bool,
    pub request_body_content_type: String,
    response_content_type: String,
    methods: Vec<String>,
    parameter_schemas: HashMap<String, AnySchema>,
    request_schemas: HashMap<String, AnySchema>,
    response_schemas: HashMap<String, AnySchema>,
    disable_response_list: HashMap<String, bool>,
    pub schemas: IndexMap<String, ReferenceOr<Schema>>,
    pub security: SecurityRequirement,
}

impl Default for FillOpenAPIOptions {
    fn default() -> Self {
        Self { force_generate_schemas: Default::default(), request_body_content_type: Default::default(), response_content_type: Default::default(), methods: Default::default(), parameter_schemas: Default::default(), request_schemas: Default::default(), response_schemas: Default::default(), disable_response_list: Default::default(), schemas: Default::default(), security: Default::default() }
    }
}
/*
struct PropertiesWithRef {
    field_name: String,
    field: String
}
*/
impl std::fmt::Display for FillOpenAPIOptions {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "request_schemas: {:?}\nschemas: {:?}", self.request_schemas, self.schemas)
    }
}
/*
pub trait RufsSchema {
    fn set_extension(&self, field_name :&str, value :Value) -> Result<(), Error>;
    //fn get_extension_mut(&self, field_name :&str, default :Value) -> ;
    fn as_object_type(&self) -> Result<ObjectType, Error>;
}

impl RufsSchema for Schema {

    fn set_extension(&self, field_name :&str, value :Value) -> Result<(), Error> {
        todo!()        
    }

    fn as_object_type(&self) -> Result<ObjectType, Error> {
        todo!()        
    }

}

impl RufsSchema for ReferenceOr<Schema> {

    fn set_extension(&self, field_name :&str, value :Value) -> Result<(), Error> {
        todo!()        
    }

    fn as_object_type(&self) -> Result<ObjectType, Error> {
        todo!()        
    }

}

impl RufsSchema for ReferenceOr<Box<Schema>> {

    fn set_extension(&self, field_name :&str, value :Value) -> Result<(), Error> {
        todo!()        
    }
    
    fn as_object_type(&self) -> Result<ObjectType, Error> {
        todo!()        
    }
    
}
*/
/*
type OpenAPISecurity struct {
}

type ContactObject struct {
    Name  string `json:"name,omitempty"`
    Url   string `json:"url,omitempty"`
    Email string `json:"email,omitempty"`
}

type InfoObject struct {
    Title       string        `json:"title"`
    Version     string        `json:"version"`
    Description string        `json:"description,omitempty"`
    Contact     ContactObject `json:"contact,omitempty"`
}

type ServerObject struct {
    Url string `json:"url"`
}

type ParameterObject struct {
    Ref         string  `json:"$ref,omitempty"`
    Name        string  `json:"name,omitempty"`
    In          string  `json:"in,omitempty"`
    Description string  `json:"description,omitempty"`
    Required    bool    `json:"required,omitempty"`
    Schema      *Schema `json:"schema,omitempty"`
}

type OperationObject struct {
    Tags        []string                    `json:"tags,omitempty"`
    Description string                      `json:"description,omitempty"`
    OperationId string                      `json:"operationId,omitempty"`
    Parameters  []ParameterObject           `json:"parameters,omitempty"`
    RequestBody *RequestBodyObject          `json:"requestBody,omitempty"`
    Responses   map[string]*ResponseObject  `json:"responses,omitempty"`
    Security    []SecurityRequirementObject `json:"security,omitempty"`
}
*/
#[derive(Serialize,Deserialize, Clone,Default)]
pub struct ForeignKey {
    pub table_ref :String,
    pub fields    :HashMap<String, String>,
}
/*
type Schema struct {
    Name               string                `json:"-"`
    PrimaryKeys        []string              `json:"x-primaryKeys,omitempty"`
    UniqueKeys         map[string][]string   `json:"x-uniqueKeys,omitempty"`
    ForeignKeys        map[string]ForeignKey `json:"x-foreignKeys,omitempty"`
    Required           []string              `json:"required,omitempty"`
    Ref                string                `json:"$ref,omitempty"`
    Type               string                `json:"type,omitempty"`
    Format             string                `json:"format,omitempty"`
    Description        string                `json:"description,omitempty"`
    Nullable           bool                  `json:"nullable,omitempty"`
    Essential          bool                  `json:"x-required,omitempty"`
    Title              string                `json:"x-title,omitempty"`
    Hiden              bool                  `json:"x-hiden,omitempty"`
    InternalName       string                `json:"x-internalName,omitempty"`
    Default            string                `json:"default,omitempty"`
    Enum               []any                 `json:"enum,omitempty"`
    EnumLabels         []string              `json:"x-enumLabels,omitempty"`
    IdentityGeneration string                `json:"x-identityGeneration,omitempty"`
    Updatable          bool                  `json:"x-updatable,omitempty"`
    Scale              int                   `json:"x-scale,omitempty"`
    Precision          int                   `json:"x-precision,omitempty"`
    MaxLength          int                   `json:"maxLength,omitempty"`
    Properties         HashMap<String,&Schema>    `json:"properties,omitempty"`
    Items              *Schema               `json:"items,omitempty"`
}

type MediaType struct {
    Schema *Schema `json:"schema"`
}

type RequestBodyObject struct {
    Required bool                        `json:"required,omitempty"`
    Ref      string                      `json:"$ref,omitempty"`
    Content  map[string]*MediaType `json:"content,omitempty"`
}

type ResponseObject struct {
    Description string                      `json:"description,omitempty"`
    Ref         string                      `json:"$ref,omitempty"`
    Content     map[string]*MediaType `json:"content,omitempty"`
}

type SecurityScheme struct {
    Type         string `json:"type"`
    Scheme       string `json:"scheme,omitempty"`
    Name         string `json:"name,omitempty"`
    In           string `json:"in,omitempty"`
    BearerFormat string `json:"bearerFormat,omitempty"`
}

type TagObject struct {
    Name        string `json:"name"`
    Description string `json:"description"`
}

type PathItemObject map[string]*OperationObject

type SecurityRequirementObject map[string][]string

type OpenAPI struct {
    Openapi    string                    `json:"openapi"`
    Info       *InfoObject               `json:"info"`
    Servers    []*ServerObject           `json:"servers,omitempty"`
    Paths      map[string]PathItemObject `json:"paths"`
    Components struct {
        Schemas         HashMap<String,&Schema>           `json:"schemas,omitempty"`
        Parameters      map[string]*ParameterObject  `json:"parameters,omitempty"`
        RequestBodies   map[string]RequestBodyObject `json:"requestBodies,omitempty"`
        Responses       map[string]ResponseObject    `json:"responses,omitempty"`
        SecuritySchemes map[string]SecurityScheme    `json:"securitySchemes,omitempty"`
    } `json:"components,omitempty"`
    Security []SecurityRequirementObject `json:"security,omitempty"`
    Tags     []TagObject                 `json:"tags,omitempty"`
}
*/
impl RufsOpenAPI for OpenAPI {
    
    fn get_schema_name_from_ref(reference: &str) -> String {
        if let Some(pos) = reference.rfind("/") {
            return reference[pos + 1..].to_string();
        }

        if let Some(pos) = reference.find("?") {
            return reference[..pos].to_string();
        }

        return reference.to_case(Case::Camel);
    }

    fn create(&mut self, security: &str) {
    /*
        if self.Openapi == "" {
            self.Openapi = "3.0.3";
        }

        if self.Info == nil {
            self.Info = &InfoObject{Title: "rufs-base-es6 openapi genetator", Version: "0.0.0", Description: "CRUD operations", Contact: ContactObject{Name: "API Support", Url: "http://www.example.com/support", Email: "support@example.com"}}
        }

        if self.Paths == nil {
            self.Paths = map[string]PathItemObject{}
        }
    */
    if self.components.is_none() {
        self.components = Some(Components::default());
    }
    /*
    if self.Components.Parameters == nil {
        self.Components.Parameters = map[string]*ParameterObject{}
    }

    if self.Components.RequestBodies == nil {
        self.Components.RequestBodies = map[string]RequestBodyObject{}
    }

    if self.Components.Responses == nil {
        self.Components.Responses = map[string]ResponseObject{}
    }
    */
    if self.components.as_ref().unwrap().security_schemes.len() == 0 {
        self.components.as_mut().unwrap().security_schemes.insert("jwt".to_owned(), ReferenceOr::Item(SecurityScheme::HTTP { scheme: "bearer".to_owned(), bearer_format: Some("JWT".to_owned()), description: None }));
        self.components.as_mut().unwrap().security_schemes.insert("apiKey".to_owned(),ReferenceOr::Item(SecurityScheme::APIKey { location: APIKeyLocation::Header, name: "X-API-KEY".to_owned(), description: None }));
        self.components.as_mut().unwrap().security_schemes.insert("basic".to_owned(),ReferenceOr::Item(SecurityScheme::HTTP { scheme: "basic".to_owned(), bearer_format: None, description: None }));
    }

    if self.security.is_none() && security.len() > 0 {
        self.security = Some(vec![IndexMap::from([(security.to_string(), vec![])])]);
    }
}
/*
func (source *OpenAPI) copy(paths []string) *OpenAPI {
    dest := &OpenAPI{}
    return dest
}

func (self *OpenAPI) convertStandartToRufs() {
    var convert_schema func(schema *Schema)

    convert_schema = func(schema *Schema) {
        for field_name, field := range schema.Properties {
            for _, value := range schema.Required {
                if value == field_name {
                    field.Essential = true
                    break
                }
            }

            if field.Format == "date-time" || field.Format == "date" {
                field.Type = field.Format
            }

            if field.Type == "object" && field.Properties != nil {
                convert_schema(field)
            } else if field.Type == "array" && field.Items != nil && field.Items.Type == "object" && field.Items.Properties != nil {
                convert_schema(field.Items)
            }
        }
    }

    for _, schema := range self.Components.Schemas {
        convert_schema(schema)
    }

    for _, request_body_object := range self.Components.RequestBodies {
        for _, media_type_object := range request_body_object.Content {
            if media_type_object.Schema.Properties != nil {
                convert_schema(media_type_object.Schema)
            }
        }
    }
}
*/

fn copy_value(&self, schema: &Schema, field_name:&String, field: &Schema, value :&Value) -> Result<Value, Error> {
    let essential = match &schema.schema_kind {
        SchemaKind::Type(typ) => match typ {
            Type::Object(object_type) => object_type.required.contains(field_name),
            _ => todo!(),
        },
        SchemaKind::Any(any) => any.required.contains(field_name),
        _ => todo!(),
    };

    if value.is_null() && essential && !field.schema_data.nullable {
        match &field.schema_kind {
            SchemaKind::Type(typ) => {
                match typ {
                    Type::String(x) => {
                        if x.enumeration.len() == 1 {
                            return Ok(json!(x.enumeration.get(0).as_ref().unwrap().as_ref().unwrap()));
                        }
                    },
                    Type::Number(x) => {
                        if x.enumeration.len() == 1 {
                            return Ok(json!(x.enumeration.get(0).unwrap().unwrap()));
                        }
                    },
                    Type::Integer(x) => {
                        if x.enumeration.len() == 1 {
                            return Ok(json!(x.enumeration.get(0).unwrap().unwrap()));
                        }
                    },
                    _ => todo!(),
                }
            },
            _ => todo!(),
        }
    
        if let Some(value) = &field.schema_data.default {
            return Ok(value.clone());
        }
    }

    if value.is_string() {
        match &field.schema_kind {
            SchemaKind::Type(typ) => {
                match typ {
                    Type::Number(_) => return Ok(json!(value.as_str().unwrap().parse::<f64>().unwrap())),
                    Type::Integer(_) => return Ok(json!(value.as_str().unwrap().parse::<i64>().unwrap())),
                    Type::Boolean {  } => return Ok(json!(value.as_str().unwrap().parse::<bool>().unwrap())),
                    _ => todo!(),
                }
            },
            _ => todo!(),
        }
    } else {
        return Ok(value.clone());
    }
}

fn get_value_from_schema<'a>(&'a self, schema :&Schema, property_name :&str, obj: &'a Value) -> Option<&Value> {
    fn process<'a>(properties: &IndexMap<String, ReferenceOr<Box<Schema>>>, property_name :&str, obj: &'a Value) -> Option<&'a Value> {
        if let Some(property) = properties.get(property_name) {
            if let ReferenceOr::Item(property) = property {
                if let Some(value) = obj.get(property_name) {
                    return Some(value);
                }
                
                if let Some(internal_name) = property.schema_data.extensions.get("x-internalName") {
                    if let Value::String(internal_name) = internal_name {
                        if let Some(value) = obj.get(internal_name) {
                            return Some(value);
                        }
                    }
                }
            }
        }

        for (field_name, property) in properties {
            if let ReferenceOr::Item(property) = property {
                if let Some(internal_name) = property.schema_data.extensions.get("x-internalName") {
                    if let Value::String(internal_name) = internal_name {
                        if internal_name == property_name {
                            return obj.get(field_name);
                        }
                    }
                }
            }
        }

        None
    }

    match &schema.schema_kind {
        SchemaKind::Type(tip) => match tip {
            Type::Object(object_type) => process(&object_type.properties, property_name, obj),
            _ => todo!(),
        },
        SchemaKind::Any(any) => process(&any.properties, property_name, obj),
        _ => todo!(),
    }
}

fn copy_fields(&self, schema: &Schema, data_in: &Value, ignorenil: bool, ignore_hiden: bool, only_primary_keys: bool) -> Result<Value, Error> {
    fn copy_properties(openapi: &OpenAPI, schema: &Schema, properties : &IndexMap<String, ReferenceOr<Box<Schema>>>, extensions: &IndexMap<String, Value>, data_in: &Value, ignorenil: bool, ignore_hiden: bool, only_primary_keys: bool) -> Result<Value, Error> {
        let mut data_out = json!({});

        for (field_name, field) in properties {
            if let Some(hiden) = extensions.get("x-hiden") {
                if ignore_hiden == true && hiden.as_bool().unwrap() == true {
                    continue;
                }
            }
    
            if data_in.get(field_name).is_none() && ignorenil {
                continue
            }
    
            if let Some(primary_keys) = extensions.get("x-primaryKeys") {
                let x = primary_keys.as_array().unwrap();

                if only_primary_keys == true && x.contains(&Value::String(field_name.to_string())) == false {
                    continue;
                }
            }
    
            let value = openapi.get_value_from_schema(schema, field_name, data_in);
    
            if value.is_none() {
                if let ReferenceOr::Item(schema) = field {
                    if schema.schema_data.nullable {
                        data_out[field_name] = Value::Null;
                    }
                }
            } else {
                data_out[field_name] = openapi.copy_value(schema, field_name, field.as_item().as_ref().unwrap().as_ref(), value.unwrap()).unwrap();
            }
        }

        Ok(data_out)
    }

    let openapi = self;
    let extensions = &schema.schema_data.extensions;

    match &schema.schema_kind {
        SchemaKind::Type(schema_type) => {
            match schema_type {
                Type::Object(object_type) => return copy_properties(openapi, schema, &object_type.properties, extensions, data_in, ignorenil, ignore_hiden, only_primary_keys),
                _ => todo!(),
            }
        },
        SchemaKind::Any(any) => {
            if any.properties.is_empty() == false {
                return copy_properties(openapi, schema, &any.properties, extensions, data_in, ignorenil, ignore_hiden, only_primary_keys);
            }
        },
        _ => todo!(),
    }

    Err(Error::new(std::io::ErrorKind::NotFound, ""))
}

    fn fill(&mut self, options: &mut FillOpenAPIOptions) -> Result<(), Error> {
        self.create("jwt");
        let force_generate_path = options.request_schemas.is_empty() && options.parameter_schemas.is_empty();

        if options.request_body_content_type == "" {
            options.request_body_content_type = "application/json".to_string();
        }

        if options.response_content_type == "" {
            options.response_content_type = "application/json".to_string();
        }

        if options.methods.len() == 0 {
            options.methods = vec!["get".to_string(), "put".to_string(), "post".to_string(), "delete".to_string(), "patch".to_string()];
        }

        if options.request_schemas.contains_key("login") == false {
            let request_schema: AnySchema =
                serde_json::from_str(r#"{"type": "object", "properties": {"user": {"type": "string"}, "password": {"type": "string"}}, "required": ["user", "password"]}"#).unwrap();
            let response_schema: Schema = serde_json::from_str(r#"{"type": "object", "properties": {"tokenPayload": {"type": "string"}}, "required": ["tokenPayload"]}"#).unwrap();
            let request_schemas = HashMap::from([("login".to_string(), request_schema)]);
            let schemas = IndexMap::from([("login".to_string(), ReferenceOr::Item(response_schema))]);
            let mut login_options = FillOpenAPIOptions {
                methods: vec!["post".to_string()],
                request_schemas,
                schemas,
                ..FillOpenAPIOptions::default()
            };
            self.fill(&mut login_options)?;
        }

        let components = self.components.as_mut().unwrap();

        if options.schemas.is_empty() {
            options.schemas = components.schemas.clone();
        } else {
            for (schema_name, schema) in &options.schemas {
                components.schemas.insert(schema_name.clone(), schema.clone());
            }
        }
        // add components/responses with error schema
        let schema_error: Schema =
            serde_json::from_str(r#"{"type": "object", "properties": {"code": {"type": "integer"}, "description": {"type": "string"}}, "required": ["code", "description"]}"#).unwrap();
        let content = IndexMap::from([(
            "application/json".to_owned(),
            MediaType {
                schema: Some(ReferenceOr::Item(schema_error)),
                ..Default::default()
            },
        )]); // map[string]*MediaType{: {Schema: }}
        components.responses.insert(
            "Error".to_string(),
            ReferenceOr::Item(Response {
                description: "Error response".to_string(),
                content,
                ..Response::default()
            }),
        );

        for (schema_name, schema) in options.schemas.clone() {
            let parameter_schema = options.parameter_schemas.get(&schema_name);
            let request_schema = options.request_schemas.get(&schema_name);

            if !options.force_generate_schemas && !force_generate_path && request_schema.is_none() && parameter_schema.is_some() {
                continue;
            }

            if self.tags.iter().find(|&item| item.name == schema_name).is_none() {
                self.tags.push(Tag {
                    name: schema_name.clone(),
                    ..Tag::default()
                });
            }

            let reference_to_schema = ReferenceOr::Reference::<Schema> {
                reference: format!("#/components/schemas/{}", schema_name),
            };
            // fill components/requestBody with schemas
            {
                let mut request_body = RequestBody {
                    required: true,
                    ..RequestBody::default()
                };

                if request_schema.is_some() && request_schema.unwrap().typ.is_some() {
                    let schema = Schema {
                        schema_data: SchemaData::default(),
                        schema_kind: SchemaKind::Any(request_schema.unwrap().clone()),
                    };
                    request_body.content.insert(
                        options.request_body_content_type.clone(),
                        MediaType {
                            schema: Some(ReferenceOr::Item(schema)),
                            ..MediaType::default()
                        },
                    );
                } else if components.request_bodies.get(&schema_name).is_none() {
                    request_body.content.insert(
                        options.request_body_content_type.clone(),
                        MediaType {
                            schema: Some(reference_to_schema.clone()),
                            ..MediaType::default()
                        },
                    );
                } else {
                    continue;
                }

                components.request_bodies.insert(schema_name.clone(), ReferenceOr::Item(request_body));
            }
            // fill components/responses with schemas
            let disable_response_list = options.disable_response_list.get(&schema_name).unwrap_or(&false);

            {
                let value = if options.response_schemas.get(&schema_name).is_none() {
                    MediaType {
                        schema: Some(reference_to_schema.clone()),
                        ..MediaType::default()
                    }
                } else {
                    let response_schema = Schema {
                        schema_data: SchemaData::default(),
                        schema_kind: SchemaKind::Any(options.response_schemas.get(&schema_name).unwrap().clone()),
                    };
                    MediaType {
                        schema: Some(ReferenceOr::Item(response_schema)),
                        ..MediaType::default()
                    }
                };

                let mut content: IndexMap<String, MediaType> = IndexMap::new();
                content.insert(options.response_content_type.clone(), value);
                let response: ReferenceOr<Response> = ReferenceOr::Item(Response {
                    description: "response".to_string(),
                    content,
                    ..Response::default()
                });
                components.responses.insert(schema_name.clone(), response);

                if !disable_response_list {
                    let reference_to_schema = ReferenceOr::Reference::<Box<Schema>> {
                        reference: format!("#/components/schemas/{}", schema_name),
                    };
                    let items = Some(reference_to_schema);
                    let schema: AnySchema = AnySchema {
                        typ: Some("array".to_string()),
                        items,
                        ..AnySchema::default()
                    };
                    let schema = Schema {
                        schema_data: SchemaData::default(),
                        schema_kind: SchemaKind::Any(schema),
                    };
                    let mut content: IndexMap<String, MediaType> = IndexMap::new();
                    content.insert(
                        options.request_body_content_type.clone(),
                        MediaType {
                            schema: Some(ReferenceOr::Item(schema)),
                            ..MediaType::default()
                        },
                    );
                    components.responses.insert(
                        format!("{}List", schema_name),
                        ReferenceOr::Item(Response {
                            description: "response list".to_string(),
                            content,
                            ..Response::default()
                        }),
                    );
                }
            }
            // fill components/parameters with primaryKeys
            if parameter_schema.is_some() {
                let schema = ReferenceOr::Item(Schema {
                    schema_kind: SchemaKind::Any(parameter_schema.unwrap().clone()),
                    schema_data: SchemaData::default(),
                });
                let examples: IndexMap<String, ReferenceOr<Example>> = IndexMap::new();
                let extensions: IndexMap<String, serde_json::Value> = IndexMap::new();
                let parameter_data = ParameterData {
                    name: "main".to_string(),
                    required: true,
                    format: ParameterSchemaOrContent::Schema(schema),
                    description: None,
                    deprecated: None,
                    example: None,
                    explode: None,
                    examples,
                    extensions,
                };
                components.parameters.insert(
                    schema_name.clone(),
                    ReferenceOr::Item(Parameter::Query {
                        parameter_data,
                        allow_reserved: false,
                        style: QueryStyle::default(),
                        allow_empty_value: None,
                    }),
                );
            } else {
                if schema.as_item().unwrap().schema_data.extensions.get("x-primaryKeys").is_some() {
                    let required = schema
                        .as_item()
                        .unwrap()
                        .schema_data
                        .extensions
                        .get("x-primaryKeys")
                        .unwrap()
                        .as_array()
                        .unwrap()
                        .iter()
                        .map(|x| x.as_str().unwrap().to_string())
                        .collect();
                    let mut schema_primary_key = AnySchema {
                        typ: Some("object".to_string()),
                        required,
                        ..Default::default()
                    };

                    for key in &schema_primary_key.required {
                        if let SchemaKind::Any(schema) = schema.as_item().unwrap().schema_kind.clone() {
                            schema_primary_key.properties.insert(key.clone(), schema.properties.get(key).unwrap().clone());
                        }
                    }

                    let examples: IndexMap<String, ReferenceOr<Example>> = IndexMap::new();
                    let extensions: IndexMap<String, serde_json::Value> = IndexMap::new();
                    let parameter = Parameter::Query {
                        parameter_data: ParameterData {
                            name: "primaryKey".to_string(),
                            required: true,
                            format: ParameterSchemaOrContent::Schema(ReferenceOr::Item(Schema {
                                schema_kind: SchemaKind::Any(schema_primary_key),
                                schema_data: SchemaData::default(),
                            })),
                            description: None,
                            deprecated: None,
                            example: None,
                            examples,
                            explode: None,
                            extensions,
                        },
                        allow_reserved: false,
                        style: QueryStyle::Form,
                        allow_empty_value: None,
                    };
                    components.parameters.insert(schema_name.clone(), ReferenceOr::Item(parameter));
                }
            }
            // path
            let path_name = format!("/{}", schema_name.to_case(Case::Snake));
            let mut path_item_object = PathItem::default();
            let responses_ref_ok: ReferenceOr<Response> = ReferenceOr::Reference {
                reference: format!("#/components/responses/{}", schema_name),
            };
            let responses_ref_ok_list: ReferenceOr<Response> = ReferenceOr::Reference {
                reference: format!("#/components/responses/{}List", schema_name),
            };
            let responses_ref_error: ReferenceOr<Response> = ReferenceOr::Reference {
                reference: "#/components/responses/Error".to_string(),
            };
            let parameters_ref: ReferenceOr<Parameter> = ReferenceOr::Reference {
                reference: format!("#/components/parameters/{}", schema_name),
            };
            let request_body_ref: ReferenceOr<RequestBody> = ReferenceOr::Reference {
                reference: format!("#/components/requestBodies/{}", schema_name),
            };

            let methods = ["get", "put", "post", "delete", "patch"];
            let methods_have_parameters = [true, true, false, true, true];
            let methods_have_request_body = [false, true, true, false, true];
            let methods_have_response_list = [true, false, false, false, false];

            for i in 0..methods.len() {
                let method = methods[i];

                if options.methods.contains(&method.to_string()) == false {
                    continue;
                }

                let mut operation_object = Operation::default();

                if options.methods.len() > 1 {
                    operation_object.operation_id = Some(format!("zzz_{}_{}", method, schema_name.clone()));
                } else {
                    operation_object.operation_id = Some(schema_name.clone());
                }

                if methods_have_parameters[i] && components.parameters.get(&schema_name).is_some() {
                    operation_object.parameters.push(parameters_ref.clone());
                }

                if methods_have_request_body[i] {
                    operation_object.request_body = Some(request_body_ref.clone());
                }

                if methods_have_response_list[i] && !disable_response_list {
                    operation_object.responses.responses.insert(StatusCode::Code(200), responses_ref_ok_list.clone());
                } else {
                    operation_object.responses.responses.insert(StatusCode::Code(200), responses_ref_ok.clone());
                }

                operation_object.responses.default = Some(responses_ref_error.clone());
                operation_object.tags.push(schema_name.clone());
                operation_object.description = Some(format!("CRUD {} operation over {}", method, schema_name));

                if options.security.is_empty() == false {
                    operation_object.security = Some(vec![options.security.clone()]);
                }

                if !methods_have_parameters[i] || operation_object.parameters.is_empty() == false {
                    match method {
                        "get" => path_item_object.get = Some(operation_object),
                        "put" => path_item_object.put = Some(operation_object),
                        "post" => path_item_object.post = Some(operation_object),
                        "delete" => path_item_object.delete = Some(operation_object),
                        "patch" => path_item_object.patch = Some(operation_object),
                        &_ => todo!(),
                    }
                }
            }

            self.paths.paths.insert(path_name, ReferenceOr::Item(path_item_object));
        }

        Ok(())
    }

    fn get_schema_from_schemas(&self, reference :&str) -> Option<&Schema> {
        let schema_name = OpenAPI::get_schema_name_from_ref(reference);
        println!("[OpenAPI.get_schema_from_schemas({reference})] : {}", schema_name);
        let schema = self.components.as_ref().unwrap().schemas.get(&schema_name)?;

        return match schema {
            ReferenceOr::Item(schema) => Some(schema),
            _ => None,
        };
    }

    fn get_schema_from_request_bodies(&self, schema_name: &str) -> Option<&Schema> {
        let schema_name = OpenAPI::get_schema_name_from_ref(schema_name);
        let request_body_object = self.components.as_ref().unwrap().request_bodies.get(&schema_name)?.as_item()?;

        for (_, media_type_object) in &request_body_object.content {
            match media_type_object.schema.as_ref()? {
                ReferenceOr::Item(schema) => {
//                    if media_type_object.schema.Properties.is_some() {
                        return Some(schema)
//                    }
                },
                ReferenceOr::Reference { reference } => match self.get_schema_from_ref(reference) {
                    Ok(schema) => return Some(schema),
                    Err(_) => return None,
                },
            }
        }

        None
    }

    fn get_schema_from_responses(&self, schema_name: &str) -> Option<&Schema> {
        let openapi = self;
        let schema_name = &OpenAPI::get_schema_name_from_ref(schema_name);
        let response_object = match openapi.components.as_ref().unwrap().responses.get(schema_name) {
            Some(response_object) => response_object.as_item().unwrap(),
            None => return None,
        };

        for (_, media_type_object) in &response_object.content {
            match media_type_object.schema.as_ref().unwrap() {
                ReferenceOr::Reference { reference } => return Some(openapi.get_schema_from_ref(reference).unwrap()),
                ReferenceOr::Item(schema) => {
                    match &schema.schema_kind {
                        SchemaKind::Type(typ) => {
                            match typ {
                                Type::Array(_) => return Some(&schema),
                                _ => todo!(),
                            }
                        },
                        SchemaKind::OneOf { one_of: _ } => todo!(),
                        SchemaKind::AllOf { all_of:_ } => todo!(),
                        SchemaKind::AnyOf { any_of:_ } => todo!(),
                        SchemaKind::Not { not:_ } => todo!(),
                        SchemaKind::Any(any) => {
                            if any.items.is_some() {
                                return Some(&schema);
                            }
                        },
                    }
                }
            }
        }

        None
    }

    fn get_schema_from_ref(&self, reference: &str) -> Result<&Schema, Error> {
        let openapi = self;
        let schema_name = OpenAPI::get_schema_name_from_ref(reference);
        println!("[OpenAPI.get_schema_from_ref({reference})]");

        let schema = if reference.starts_with("#/components/parameters/") {
            if let Some(parameter_object) = openapi.components.as_ref().unwrap().parameters.get(&schema_name) {
                match &parameter_object {
                    ReferenceOr::Reference { reference: _ } => todo!(),
                    ReferenceOr::Item(parameter) => match &parameter {
                        Parameter::Query {
                            parameter_data,
                            allow_reserved: _,
                            style: _,
                            allow_empty_value: _,
                        } => match &parameter_data.format {
                            ParameterSchemaOrContent::Schema(schema) => schema,
                            ParameterSchemaOrContent::Content(_) => todo!(),
                        },
                        Parameter::Header { parameter_data: _, style: _ } => todo!(),
                        Parameter::Path { parameter_data: _, style: _ } => todo!(),
                        Parameter::Cookie { parameter_data: _, style: _ } => todo!(),
                    },
                }
            } else {
                return Err(Error::new(
                    std::io::ErrorKind::NotFound,
                    format!("[OpenAPI.get_schema_from_parameters] don't find schema from {}", reference),
                ));
            }
        } else if reference.starts_with("#/components/schemas/") {
            let aux = openapi.components.as_ref().unwrap().schemas.get(&schema_name).unwrap();
            aux
        } else if reference.starts_with("#/components/responses/") {
            let aux = openapi.components.as_ref().unwrap().responses.get(&schema_name).unwrap().as_item().unwrap().content.first().unwrap().1.schema.as_ref().unwrap();
            aux
        } else {
            return Err(Error::new(
                std::io::ErrorKind::NotFound,
                format!("[OpenAPI.get_schema_from_parameters] don't find schema from {}", reference),
            ));
        };

        match schema {
            ReferenceOr::Reference { reference } => return self.get_schema_from_ref(reference),
            ReferenceOr::Item(schema) => match &schema.schema_kind {
                SchemaKind::Type(typ) => {
                    match typ {
                        Type::Object(_) => Ok(&schema),
                        Type::String(_) => todo!(),
                        Type::Number(_) => todo!(),
                        Type::Integer(_) => todo!(),
                        Type::Array(array) => match &array.items {
                            Some(schema) => match schema {
                                ReferenceOr::Reference { reference } => self.get_schema_from_ref(reference),
                                ReferenceOr::Item(schema) => Ok(schema),
                            },
                            None => todo!(),
                        },
                        Type::Boolean {  } => todo!(),
                    }
                },
                SchemaKind::OneOf { one_of: _ } => todo!(),
                SchemaKind::AllOf { all_of: _ } => todo!(),
                SchemaKind::AnyOf { any_of: _ } => todo!(),
                SchemaKind::Not { not: _ } => todo!(),
                SchemaKind::Any(_) => Ok(&schema),
            },
        }
    }

    fn get_path_params(&self, uri: &str, _params: &Value) -> Result<String, Error> {
        let openapi = self;
        let uri_segments: Vec<&str> = uri.split('/').collect();

        for (pattern, _) in openapi.paths.iter() {
            let path_segments: Vec<&str> = pattern.split('/').collect();

            if uri_segments.len() == path_segments.len() {
                let mut matched = true;

                for (idx, path_segment) in path_segments.iter().enumerate() {
                    if path_segment.starts_with("{") && path_segment.ends_with("}") {
                        //let name = path_segment[1..path_segment.len()-1].to_string();
                        //params.as_object_mut().unwrap().insert(name, Value::String(uri_segments[idx].to_string()));
                    } else if *path_segment != uri_segments[idx] {
                        matched = false;
                        break;
                    }
                }

                if matched {
                    return Ok(pattern.to_string());
                }
            }
        }

        Err(Error::new(std::io::ErrorKind::NotFound, ""))
    }

    fn get_schema_from_parameters(&self, path: &str, method: &str) -> Result<&Schema, Error> {
        let openapi = self;

        for (pattern, path_item_object) in &openapi.paths.paths {
            if pattern == path {
                if let Some(operation_object) = path_item_object.as_item().unwrap().iter().find(|x| x.0 == method) {
                    for parameter_object in &operation_object.1.parameters {
                        match &parameter_object {
                            ReferenceOr::Reference { reference } => return openapi.get_schema_from_ref(reference),
                            ReferenceOr::Item(parameter_object) => {
                                match &parameter_object.parameter_data_ref().format {
                                    ParameterSchemaOrContent::Schema(schema) => {
                                        match &schema {
                                            ReferenceOr::Item(schema) => {
                                                match &schema.schema_kind {
                                                    SchemaKind::Type(typ) => match typ {
                                                        Type::String(_) => todo!(),
                                                        Type::Number(_) => todo!(),
                                                        Type::Integer(_) => todo!(),
                                                        Type::Object(_) => return Ok(schema),
                                                        Type::Array(_) => todo!(),
                                                        Type::Boolean {  } => todo!(),
                                                    },
                                                    _ => todo!(),
                                                }
                                            },
                                            _ => todo!(),
                                        }
                                    },
                                    ParameterSchemaOrContent::Content(_) => todo!(),
                                }
                            },
                        }
                    }
                }
            }
        }

        Err(Error::new(std::io::ErrorKind::NotFound, format!("[OpenAPI.get_schema_from_parameters] don't find schema parameter from {}", path)))
    }

    fn get_schema(&self, path :&str, method :&str, typ :&str) -> Result<&Schema, Error> {
        fn get_schema_from_content<'a>(openapi: &'a OpenAPI, content :&'a Content) -> Result<&'a Schema, Error> {
            for (_, media_type_object) in content {
                match media_type_object.schema.as_ref().unwrap() {
                    ReferenceOr::Reference { reference } => {
                        return openapi.get_schema_from_ref(reference);
                    },
                    ReferenceOr::Item(schema) => {
                        let schema = match &schema.schema_kind {
                            SchemaKind::Type(typ) => {
                                match typ {
                                    Type::Object(_) => schema,
                                    _ => todo!(),
                                }
                            },
                            _ => todo!(),
                        };
                        return Ok(schema);
                    }
                };
            }

            Err(Error::new(std::io::ErrorKind::NotFound, ""))
        }

        if let Some(path_item_object) = self.paths.paths.get(path) {
            let path_item_object = match path_item_object {
                ReferenceOr::Reference { reference: _ } => todo!(),
                ReferenceOr::Item(path_item_object) => path_item_object,
            };

            if let Some((_, operation_object)) = path_item_object.iter().find(|x| x.0 == method) {
                if typ == "responseObject" {
                    if let Some(response_object) = operation_object.responses.responses.get(&StatusCode::Code(200)) {
                        match response_object {
                            ReferenceOr::Item(response_object) => return get_schema_from_content(self, &response_object.content),
                            ReferenceOr::Reference { reference } => {
                                if let Some(schema) = self.get_schema_from_responses(reference) {
                                    return Ok(schema);
                                } else {
                                    return Err(Error::new(std::io::ErrorKind::NotFound, ""));
                                }
                            },
                        };
                    } else {
                        return Err(Error::new(std::io::ErrorKind::NotFound, ""));
                    }
                } else {
                    return Err(Error::new(std::io::ErrorKind::NotFound, ""));
                }
            } else {
                return Err(Error::new(std::io::ErrorKind::NotFound, format!("[OpenAPI.get_response_schema] missing OperationObject {}.{}", path, method)));
            }
        } else {
            return Err(Error::new(std::io::ErrorKind::NotFound, format!("[OpenAPI.get_response_schema] missing PathItemObject {}", path)));
        }
    }

    fn get_schema_name(&self, path: &str, method: &str) -> Result<String, Error> {
        let path_item_object = self.paths.paths.get(path).unwrap().as_item().unwrap();
        let method = method.to_lowercase();
        let operation_object = path_item_object.iter().find(|item| item.0 == method).unwrap().1;

        if method == "post" {
            match operation_object.request_body.as_ref().unwrap() {
                ReferenceOr::Reference { reference } => return Ok(OpenAPI::get_schema_name_from_ref(&reference)),
                ReferenceOr::Item(_) => todo!(),
            }
        } else {
            let response_object = operation_object.responses.responses.get(&StatusCode::Code(200));

            if response_object.is_some() {
                let schema = match &response_object.unwrap() {
                    ReferenceOr::Reference { reference } => self.get_schema_from_ref(reference).unwrap(),
                    ReferenceOr::Item(response) => match &response.content.first().as_ref().unwrap().1.schema.as_ref().unwrap() {
                        ReferenceOr::Reference { reference } => {
                            return Ok(OpenAPI::get_schema_name_from_ref(&reference))
                        },
                        ReferenceOr::Item(schema) => schema,
                    },
                };

                match &schema.schema_kind {
                    SchemaKind::Type(typ) => match typ {
                        Type::Array(array) => {
                            match array.items.as_ref().unwrap() {
                                ReferenceOr::Reference { reference } => {
                                    println!("[OpenAPI.get_schema_name({path}, {method})] : SchemaKind::Type::Array : {}", reference);
                                    return Ok(OpenAPI::get_schema_name_from_ref(&reference))
                                },
                                ReferenceOr::Item(_) => todo!(),
                            }
                        },
                        _ => todo!(),
                    },
                    SchemaKind::Any(_) => {
                        let schema_name = path[1..].to_string().to_case(Case::Camel);
                        return Ok(schema_name)
                    },
                    _ => todo!(),
                }
            }
        }

        Err(Error::new(std::io::ErrorKind::NotFound, ""))
    }

    fn get_properties_from_schema<'a>(&'a self, schema :&'a Schema) -> Option<&'a IndexMap<String, ReferenceOr<Box<Schema>>>> {
        match &schema.schema_kind {
            SchemaKind::Type(typ) => match typ {
                Type::Object(object) => Some(&object.properties),
                _ => None,
            },
            SchemaKind::Any(any) => Some(&any.properties),
            _ => None,
        }
    }

    fn get_properties_from_schema_name<'a>(&'a self, schema_name :&str) -> Option<&'a IndexMap<String, ReferenceOr<Box<Schema>>>> {
        let schema = self.get_schema_from_schemas(schema_name)?;
        self.get_properties_from_schema(schema)
    }

    fn get_property_from_schema<'a>(&'a self, schema :&'a Schema, property_name :&'a str) -> Option<&'a Schema> {
        let properties = self.get_properties_from_schema(schema)?;

        if let Some(value) = properties.get(property_name) {
            match value {
                ReferenceOr::Item(item) => return Some(item),
                ReferenceOr::Reference { reference } => match self.get_schema_from_ref(reference) {
                    Ok(schema) => return Some(schema),
                    Err(_) => todo!(),
                },
            }
        }

        for (_, field) in properties {
            match field {
                ReferenceOr::Item(item) => {
                    if let Some(internal_name) = item.schema_data.extensions.get("x-internalName") {
                        if internal_name == property_name {
                            return Some(item);
                        }
                    }
                },
                _ => continue,
            }
        }

        None
    }

    fn get_property_from_schemas<'a>(&'a self, schema_name: &str, property_name :&'a str) -> Option<&Schema> {
        let schema = self.get_schema_from_schemas(schema_name)?;
        self.get_property_from_schema(schema, property_name)
    }

    fn get_property_from_request_bodies<'a>(&'a self, schema_name :&str, property_name :&'a str) -> Option<&Schema> {
        let schema = self.get_schema_from_request_bodies(schema_name)?;
        let field = self.get_property_from_schema(schema, property_name);
        field
    }

    fn get_property<'a>(&'a self, schema_name :&str, property_name :&'a str) -> Option<&Schema> {
        let schema_name = OpenAPI::get_schema_name_from_ref(schema_name);
        let field = self.get_property_from_schemas(&schema_name, property_name);

        if field.is_none() {
            return self.get_property_from_request_bodies(&schema_name, property_name);
        }

        field
    }
/*
    fn get_properties_with_ref(&self, schema_name :&str, reference :&str) -> Vec<PropertiesWithRef> {
        fn process_schema(schema :&Schema, reference :&str, mut list_out: &Vec<PropertiesWithRef>) {
            fn process_properties(properties: &IndexMap<String, ReferenceOr<Box<Schema>>>, reference :&str, mut list_out: &Vec<PropertiesWithRef>) {
                for (field_name, field) in properties {
                    match field {
                        ReferenceOr::Reference { reference } => {
                            if reference == reference {
                                let found = false;
        
                                for item in list_out {
                                    if &item.field_name == field_name {
                                        found = true;
                                        break;
                                    }
                                }
        
                                if !found {
                                    list_out.push(PropertiesWithRef{field_name: field_name.clone(), field: reference.clone()});
                                }
                            }
                        },
                        ReferenceOr::Item(_) => todo!(),
                    }
                }
            }

            match &schema.schema_kind {
                SchemaKind::Type(typ) => match typ {
                    Type::Object(object) => process_properties(&object.properties, reference, list_out),
                    _ => todo!(),
                },
                SchemaKind::Any(any) => process_properties(&any.properties, reference, list_out),
                _ => todo!(),
            }
        }

        let schema_name = OpenAPI::get_schema_name_from_ref(schema_name);
        let schema = self.get_schema_from_schemas(&schema_name);
        let mut list;

        if schema.is_some() {
            process_schema(schema.unwrap(), reference, &list);
        }

        let schema = self.get_schema_from_request_bodies(&schema_name);

        if schema.is_some() {
            process_schema(schema.unwrap(), reference, &list);
        }

        return list;
    }
*/
    // (service, (service.field|foreign_table_name)
    fn get_foreign_key_description(&self, schema :&str, field_name: &str) -> Result<Option<ForeignKeyDescription>, Error> {
        let field = self.get_property(schema, field_name);

        if field.is_none() {
            println!("[openapi.get_foreign_key_description({}, {})] trace : missing property in schema", schema, field_name);
            return Ok(None);
        }

        let reference = field.unwrap().schema_data.extensions.get("$ref");

        if reference.is_none() {
            println!("[openapi.get_foreign_key_description({}, {})] : trace : missing $ref \n{:?}", schema, field_name, field);
            return Ok(None);
        }

        let reference = reference.unwrap().as_str().unwrap();
        let service_ref = self.get_schema_from_schemas(reference);

        if service_ref.is_none() {
            return Err(Error::new(std::io::ErrorKind::NotFound, format!("Don't found schema {}", reference)));
        }

        let mut fields_ref  = json!({});

        if let Some(primary_keys) = service_ref.unwrap().schema_data.extensions.get("x-primaryKeys") {
            for (primary_key, _) in primary_keys.as_object().unwrap() {
                fields_ref[primary_key] = Value::Null;
            }
        }

        if fields_ref.as_object().unwrap().len() == 1 {
            for (_, value) in fields_ref.as_object_mut().unwrap() {
                value.clone_from(&Value::String(field_name.to_string()));
            }
        } else if fields_ref.as_object().unwrap().len() > 1 {
            for (field_ref, value) in fields_ref.as_object_mut().unwrap() {
                let property = self.get_property(reference, field_ref);

                if property.is_some() && value.is_null() {
                    value.clone_from(&Value::String(field_ref.clone()));
                }
            }

            for (_, value) in fields_ref.as_object_mut().unwrap() {
                if value.as_str().unwrap() == "id" {
                    value.clone_from(&Value::String(field_name.to_string()));
                }
            }
        }

        for (field_ref, value) in fields_ref.as_object().unwrap() {
            if value.is_null() {
                return Err(Error::new(std::io::ErrorKind::NotFound, format!("[OpenAPI.getForeignKeyDescription({}, {})] : don't pair with key {} : {}", schema, field_name, field_ref, fields_ref)));
            }
        }

        let ret = ForeignKeyDescription{
            //table_ref: reference.to_string(), 
            fields_ref: fields_ref, 
            //is_unique_key: true
        };

        Ok(Some(ret))
    }

    fn get_primary_key_foreign(&self, schema_name :&str, field_name :&str, obj :&Value) -> Result<Option<PrimaryKeyForeign>, Error> {
        fn process(openapi :&OpenAPI, schema :&Schema, schema_name :&str, field_name :&str, obj :&Value) -> Result<Option<PrimaryKeyForeign>, Error> {
            let foreign_key_description = openapi.get_foreign_key_description(schema_name, field_name)?;

            if foreign_key_description.is_none() {
                return Ok(None);
            }

            let foreign_key_description = foreign_key_description.unwrap();
            let key = json!({});
            let mut ret = PrimaryKeyForeign{
                //table: foreign_key_description.table_ref, 
                primary_key: key, 
                valid: false, 
                //is_unique_key: foreign_key_description.is_unique_key
            };

            for (field_ref, field_name_map) in foreign_key_description.fields_ref.as_object().unwrap() {
                match field_name_map {
                    Value::String(str) => {
                        if str.starts_with("*") {
                            ret.primary_key[field_ref] = Value::String(str[1..].to_string());
                        } else {
                            if let Some(value) = openapi.get_value_from_schema(schema, str, obj) {
                                if value.is_string() && value.as_str().unwrap().len() > 0 {
                                    ret.primary_key[field_ref] = value.clone();
                                } else {
                                    ret.valid = false;
                                }

                            } else {
                                ret.valid = false
                            }
                        }
                    },
                    _ => ret.valid = false,
                }
            }

            Ok(Some(ret))
        }

        let schema_name = OpenAPI::get_schema_name_from_ref(&schema_name);

        if let Some(schema) = self.get_schema_from_request_bodies(&schema_name) {
            return process(self, schema, &schema_name, field_name, obj);
        }

        if let Some(schema) = self.get_schema_from_schemas(&schema_name) {
            return process(self, schema, &schema_name, field_name, obj);
        }

        Err(Error::new(std::io::ErrorKind::NotFound, format!("[OpenAPI.get_primary_key_foreign({}, {})] : don't find schema.", schema_name, field_name)))
    }
}
