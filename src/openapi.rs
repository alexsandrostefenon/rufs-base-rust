use std::{collections::HashMap};

use convert_case::{Case, Casing};
use indexmap::IndexMap;
use openapiv3::*;
use serde::{Serialize, Deserialize};
use serde_json::{Value, json};

use std::fmt;

#[derive(Debug)]
pub struct Error {
    msg :String
}

impl Error {

    pub fn new(msg: String) -> Self {
        Self {msg}
    }

}

impl fmt::Display for Error {

    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", &self.msg)
    }

}

impl std::error::Error for Error {}

#[derive(PartialEq, Debug, Clone)]
pub enum SchemaPlace {Request, Response, Parameter, Schemas}

impl Default for SchemaPlace {
    fn default() -> Self { SchemaPlace::Schemas }
}

impl std::fmt::Display for SchemaPlace {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SchemaPlace::Request => write!(f, "{:?}", SchemaPlace::Request),
            SchemaPlace::Response => write!(f, "{:?}", SchemaPlace::Response),
            SchemaPlace::Parameter => write!(f, "{:?}", SchemaPlace::Parameter),
            SchemaPlace::Schemas => write!(f, "{:?}", SchemaPlace::Schemas),
        }
    }
}

impl SchemaPlace {

    pub fn from_str(name :&str) -> SchemaPlace {
        match name {
            "request" => SchemaPlace::Request,
            "response" => SchemaPlace::Response,
            "parameter" => SchemaPlace::Parameter,
            _ => SchemaPlace::Schemas
        }
    }

}
#[derive(Serialize,Debug)]
pub struct Dependent {
    pub schema:       String,
    pub field:       String,
}

#[derive(Serialize,Debug,Default)]
pub struct ForeignKeyDescription {
    schema_ref: String,
    fields_ref: HashMap<String, String>,
    //is_unique_key: bool
}

#[derive(Serialize,Debug)]
pub struct PrimaryKeyForeign {
    pub schema:       String,
    pub primary_key:  Value,
    pub valid:       bool,
    //is_unique_key: bool
}

pub trait RufsOpenAPI {
    fn get_schema_name_from_ref(reference: &str) -> String;
    fn create(&mut self, security: &str);
    fn copy_value_field(&self, field: &Schema, essential: bool, value :&Value) -> Result<Value, Error>;
    fn copy_value(&self, path :&str, method :&str, schema_place :&SchemaPlace, may_be_array: bool, property_name :&str, value :&Value) -> Result<Value, Error>;
    fn get_value_from_properties<'a>(&'a self, properties: &IndexMap<String, ReferenceOr<Box<Schema>>>, property_name :&str, obj: &'a Value) -> Option<&'a Value>;    
    fn get_value_from_schema<'a>(&'a self, schema :&Schema, property_name :&str, obj: &'a Value) -> Option<&Value>;
    fn copy_fields_using_properties(&self, properties: &IndexMap<String, ReferenceOr<Box<Schema>>>, extensions: &IndexMap<String, Value>, may_be_array: bool, data_in: &Value, ignore_null: bool, ignore_hidden: bool, only_primary_keys: bool) -> Result<Value, Error>;    
    fn copy_fields(&self, path :&str, method :&str, schema_place :&SchemaPlace, may_be_array: bool, data_in: &Value, ignorenil: bool, ignore_hidden: bool, only_primary_keys: bool) -> Result<Value, Error>;
    fn fill(&mut self, options: &mut FillOpenAPIOptions) -> Result<(), Error>;
    fn get_schema_from_schemas(&self, reference :&str) -> Option<&Schema>;
    fn get_schema_from_request_bodies(&self, schema_name: &str, may_be_array: bool) -> Option<&Schema>;
    fn get_schema_from_responses(&self, schema_name: &str, may_be_array: bool) -> Option<&Schema>;
    fn get_schema_from_operation_object_parameters<'a>(&'a self, operation_object: &'a Operation, may_be_array: bool) -> Result<&Schema, Error>;
    fn get_schema_from_parameters(&self, path: &str, method: &str, may_be_array: bool) -> Result<&Schema, Error>;
    fn get_schema(&self, path :&str, method :&str, schema_place :&SchemaPlace, may_be_array: bool) -> Result<&Schema, Error>;
    fn get_schema_from_ref(&self, reference: &str, may_be_array: bool) -> Result<&Schema, Error>;
    fn get_path_params(&self, uri: &str, params: &Value) -> Result<String, Error>;
    fn get_schema_name(&self, path: &str, method: &str, may_be_array: bool) -> Result<String, Error>;
    fn get_properties_from_schema_name<'a>(&'a self, parent_name: &Option<String>, schema_name :&str, schema_place :&SchemaPlace) -> Option<&'a IndexMap<String, ReferenceOr<Box<Schema>>>>;
    fn get_properties_from_schema<'a>(&'a self, schema :&'a Schema) -> Option<&'a IndexMap<String, ReferenceOr<Box<Schema>>>>;
    fn get_property_from_schema<'a>(&'a self, schema :&'a Schema, property_name :&str) -> Option<&'a Schema>;
    fn get_property_from_schemas<'a>(&'a self, schema_name: &str, property_name :&'a str) -> Option<&Schema>;
    fn get_property_from_request_bodies<'a>(&'a self, schema_name :&str, property_name :&'a str) -> Option<&Schema>;
    fn get_property<'a>(&'a self, schema_name :&str, property_name :&'a str) -> Option<&Schema>;
    fn get_property_mut<'a>(&'a mut self, schema_name: &'a str, field_name: &'a str) -> Option<&'a mut Box<Schema>>;
    fn get_property_from(&self, path :&str, method :&str, schema_place :&SchemaPlace, may_be_array: bool, property_name :&str) -> Option<&Schema>;
    //fn get_properties_with_ref(&self, schema_name :&str, reference :&str) -> Vec<PropertiesWithRef>;
    fn get_dependencies(&self, schema_name: &str, list: &mut Vec<String>);
    fn get_dependents(&self, schema_name_target: &str, only_in_document :bool) -> Vec<Dependent>;
    fn get_foreign_key_description(&self, schema :&str, field_name: &str) -> Result<Option<ForeignKeyDescription>, Error>;
    fn get_foreign_key(&self, schema: &str, field_name: &str, obj: &Value) -> Result<Option<Value>, Error>;
    fn get_primary_key_foreign(&self, schema_name :&str, field_name :&str, obj :&Value) -> Result<Option<PrimaryKeyForeign>, Error>;
}

#[derive(Debug)]
pub struct FillOpenAPIOptions {
    force_generate_schemas: bool,
    pub request_body_content_type: String,
    response_content_type: String,
    methods: Vec<String>,
    parameter_schemas: HashMap<String, ObjectType>,
    request_schemas: HashMap<String, ObjectType>,
    response_schemas: HashMap<String, ObjectType>,
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
#[serde(rename_all = "camelCase")]
pub struct ForeignKey {
    pub table_ref :String,
    pub fields    :HashMap<String, String>,
}

impl RufsOpenAPI for OpenAPI {
    
    fn get_schema_name_from_ref(reference: &str) -> String {
        if let Some(pos) = reference.rfind("/") {
            return reference[pos + 1..].to_string().to_case(Case::Camel);
        }

        if let Some(pos) = reference.find("?") {
            return reference[..pos].to_string().to_case(Case::Camel);
        }

        return reference.to_case(Case::Camel);
    }

    fn create(&mut self, security: &str) {
        if self.openapi.is_empty() {
            self.openapi = "3.0.3".to_string();
        }

        if self.info.title.is_empty() {
            self.info.title = "rufs-base-es6 openapi genetator".to_string();
        }

        if self.info.version.is_empty() {
            self.info.version = "0.0.0".to_string();
        }

        if self.info.description.is_none() {
            self.info.description = Some("CRUD operations".to_string());
        }

        if self.components.is_none() {
            self.components = Some(Components::default());
        }

        if self.components.as_ref().unwrap().security_schemes.len() == 0 {
            self.components.as_mut().unwrap().security_schemes.insert("jwt".to_owned(), ReferenceOr::Item(SecurityScheme::HTTP { scheme: "bearer".to_owned(), bearer_format: Some("JWT".to_owned()), description: None }));
            self.components.as_mut().unwrap().security_schemes.insert("apiKey".to_owned(),ReferenceOr::Item(SecurityScheme::APIKey { location: APIKeyLocation::Header, name: "X-API-KEY".to_owned(), description: None }));
            self.components.as_mut().unwrap().security_schemes.insert("basic".to_owned(),ReferenceOr::Item(SecurityScheme::HTTP { scheme: "basic".to_owned(), bearer_format: None, description: None }));
        }

        if self.security.is_none() && !security.is_empty() {
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
    fn copy_value_field(&self, field: &Schema, essential: bool, value :&Value) -> Result<Value, Error> {
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
                        Type::String(_) => return Ok(value.clone()),
                        Type::Object(_) => todo!(),
                        Type::Array(_) => todo!(),
                    }
                },
                _ => todo!(),
            }
        } else {
            return Ok(value.clone());
        }
    }

    fn copy_value(&self, path :&str, method :&str, schema_place :&SchemaPlace, may_be_array: bool, property_name :&str, value :&Value) -> Result<Value, Error> {
        let schema = self.get_schema(path, method, schema_place, may_be_array).unwrap();
        let field = self.get_property_from(path, method, schema_place, may_be_array, property_name).unwrap();
        let property_name = &property_name.to_string();

        let essential = match &schema.schema_kind {
            SchemaKind::Type(typ) => match typ {
                Type::Object(object_type) => object_type.required.contains(property_name),
                _ => todo!(),
            },
            SchemaKind::Any(any) => any.required.contains(property_name),
            _ => todo!(),
        };

        self.copy_value_field(field, essential, value)
    }

    fn get_value_from_properties<'a>(&'a self, properties: &IndexMap<String, ReferenceOr<Box<Schema>>>, property_name :&str, obj: &'a Value) -> Option<&'a Value> {
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

    fn get_value_from_schema<'a>(&'a self, schema :&Schema, property_name :&str, obj: &'a Value) -> Option<&Value> {
        match &schema.schema_kind {
            SchemaKind::Type(tip) => match tip {
                Type::Object(object_type) => self.get_value_from_properties(&object_type.properties, property_name, obj),
                _ => todo!(),
            },
            SchemaKind::Any(any) => self.get_value_from_properties(&any.properties, property_name, obj),
            _ => todo!(),
        }
    }

    fn copy_fields_using_properties(&self, properties: &IndexMap<String, ReferenceOr<Box<Schema>>>, extensions: &IndexMap<String, Value>, _may_be_array: bool, data_in: &Value, ignore_null: bool, ignore_hidden: bool, only_primary_keys: bool) -> Result<Value, Error> {
        let mut data_out = json!({});

        for (field_name, field) in properties {
            if let Some(hidden) = extensions.get("x-hidden") {
                if ignore_hidden == true && hidden.as_bool().unwrap() == true {
                    continue;
                }
            }
    
            if let Some(primary_keys) = extensions.get("x-primaryKeys") {
                let primary_keys = primary_keys.as_array().unwrap();

                if only_primary_keys == true && primary_keys.contains(&Value::String(field_name.to_string())) == false {
                    continue;
                }
            }
    
            if let Some(value) = self.get_value_from_properties(properties, field_name, data_in) {
                match field {
                    ReferenceOr::Reference { reference: _ } => todo!(),
                    ReferenceOr::Item(field) => data_out[field_name] = self.copy_value_field(field, !ignore_null, value)?,
                }                
            } else {
                if ignore_null {
                    continue;
                }

                if let ReferenceOr::Item(schema) = field {
                    if schema.schema_data.nullable {
                        continue;
                    }

                    if schema.schema_data.extensions.contains_key("x-identityGeneration") {
                        continue;
                    }
                }

                return Err(Error::new(format!("[RufsOpenAPI.copy_fields] field {} is null", field_name)));
            }
        }

        Ok(data_out)
    }

    fn copy_fields(&self, path :&str, method :&str, schema_place :&SchemaPlace, may_be_array: bool, data_in: &Value, ignore_null: bool, ignore_hidden: bool, only_primary_keys: bool) -> Result<Value, Error> {
        println!("[copy_fields({}, {}, {:?}, {}, {:?}, {}, {}, {})]", path, method, schema_place, may_be_array, data_in, ignore_null, ignore_hidden, only_primary_keys);
        let schema = self.get_schema(path, method, schema_place, may_be_array).unwrap();
        let extensions = &schema.schema_data.extensions;
        let properties = self.get_properties_from_schema(schema).unwrap();
        self.copy_fields_using_properties(properties, extensions, may_be_array, data_in, ignore_null, ignore_hidden, only_primary_keys)
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
            let request_schema: ObjectType = serde_json::from_str(r#"{"type": "object", "properties": {"user": {"type": "string"}, "password": {"type": "string"}}, "required": ["user", "password"]}"#).unwrap();
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
            let schema_extensions_to_preserve = ["x-title"];
            let field_extensions_to_preserve = ["x-title"];
            
            for (schema_name, schema_new) in &options.schemas {
                if let Some(schema_old) = components.schemas.insert(schema_name.clone(), schema_new.clone()) {
                    let schema_new = if let Some(schema_new) = components.schemas.get_mut(schema_name) {
                        match schema_new {
                            ReferenceOr::Reference { reference: _ } => todo!(),
                            ReferenceOr::Item(schema_new) => schema_new,
                        }
                    } else {
                        todo!()
                    };

                    match &schema_old {
                        ReferenceOr::Reference { reference: _ } => todo!(),
                        ReferenceOr::Item(schema_old) => {
                            for name in schema_extensions_to_preserve {
                                if let Some(value) = schema_old.schema_data.extensions.get(name) {
                                    schema_new.schema_data.extensions.insert(name.to_string(), value.clone());
                                }
                            }

                            let properties_old = match &schema_old.schema_kind {
                                SchemaKind::Type(schema_old) => {
                                    match &schema_old {
                                        Type::String(_) => todo!(),
                                        Type::Number(_) => todo!(),
                                        Type::Integer(_) => todo!(),
                                        Type::Object(schema_old) => Some(&schema_old.properties),
                                        Type::Array(_) => todo!(),
                                        Type::Boolean {  } => todo!(),
                                    }
                                },
                                SchemaKind::OneOf { one_of: _ } => todo!(),
                                SchemaKind::AllOf { all_of: _ } => todo!(),
                                SchemaKind::AnyOf { any_of: _ } => todo!(),
                                SchemaKind::Not { not: _ } => todo!(),
                                SchemaKind::Any(_) => None,
                            };

                            if let Some(properties_old) = properties_old {
                                for (property_name, property_old) in properties_old {
                                    match property_old {
                                        ReferenceOr::Reference { reference: _ } => todo!(),
                                        ReferenceOr::Item(property_old) => {
                                            for name in field_extensions_to_preserve {
                                                if let Some(value) = property_old.schema_data.extensions.get(name) {
                                                    match &mut schema_new.schema_kind {
                                                        SchemaKind::Type(schema_new) => {
                                                            match schema_new {
                                                                Type::String(_) => todo!(),
                                                                Type::Number(_) => todo!(),
                                                                Type::Integer(_) => todo!(),
                                                                Type::Object(schema_new) => {
                                                                    if let Some(property_new) = schema_new.properties.get_mut(property_name) {
                                                                        match property_new {
                                                                            ReferenceOr::Reference { reference: _ } => todo!(),
                                                                            ReferenceOr::Item(property_new) => {
                                                                                property_new.schema_data.extensions.insert(name.to_string(), value.clone());
                                                                            },
                                                                        }
                                                                    }
                                                                },
                                                                Type::Array(_) => todo!(),
                                                                Type::Boolean {  } => todo!(),
                                                            }
                                                        },
                                                        SchemaKind::OneOf { one_of: _ } => todo!(),
                                                        SchemaKind::AllOf { all_of: _ } => todo!(),
                                                        SchemaKind::AnyOf { any_of: _ } => todo!(),
                                                        SchemaKind::Not { not: _ } => todo!(),
                                                        SchemaKind::Any(_) => todo!(),
                                                    }
                                                }
                                            }
                                        },
                                    }
                                }
                            }
                        },
                    }
                }
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

        for (schema_name, schema) in &options.schemas {
            let parameter_schema = options.parameter_schemas.get(schema_name);
            let request_schema = options.request_schemas.get(schema_name);

            if !options.force_generate_schemas && !force_generate_path && request_schema.is_none() && parameter_schema.is_some() {
                println!("[RufsOpenAPI.fill({})] 1", schema_name);
                continue;
            }

            if self.tags.iter().find(|&item| &item.name == schema_name).is_none() {
                self.tags.push(Tag {name: schema_name.clone(), ..Tag::default()});
            }

            let reference_to_schema = ReferenceOr::Reference::<Schema> {reference: format!("#/components/schemas/{}", schema_name)};
            // fill components/requestBody with schemas
            {
                let mut request_body = RequestBody {required: true, ..RequestBody::default()};

                if request_schema.is_some() {
                    let object_type = request_schema.unwrap().clone();
                    let schema = Schema {schema_data: SchemaData::default(), schema_kind: SchemaKind::Type(Type::Object(object_type))};
                    request_body.content.insert(
                        options.request_body_content_type.clone(),
                        MediaType {schema: Some(ReferenceOr::Item(schema)), ..MediaType::default()},
                    );
                    components.request_bodies.insert(schema_name.clone(), ReferenceOr::Item(request_body));
                } else if components.request_bodies.get(schema_name).is_none() {
                    request_body.content.insert(
                        options.request_body_content_type.clone(),
                        MediaType {schema: Some(reference_to_schema.clone()), ..MediaType::default()},
                    );
                    components.request_bodies.insert(schema_name.clone(), ReferenceOr::Item(request_body));
                }
            }
            // fill components/responses with schemas
            let disable_response_list = options.disable_response_list.get(schema_name).unwrap_or(&false);

            {
                let value = if options.response_schemas.get(schema_name).is_none() {
                    MediaType {
                        schema: Some(reference_to_schema.clone()),
                        ..MediaType::default()
                    }
                } else {
                    let response_schema = Schema {
                        schema_data: SchemaData::default(),
                        schema_kind: SchemaKind::Type(Type::Object(options.response_schemas.get(schema_name).unwrap().clone())),
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
                    let schema = ArrayType {items, min_items: None, max_items: None, unique_items: false};
                    let schema = Schema {
                        schema_data: SchemaData::default(),
                        schema_kind: SchemaKind::Type(Type::Array(schema)),
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
                    schema_kind: SchemaKind::Type(Type::Object(parameter_schema.unwrap().clone())),
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
                let schema = schema.as_item().unwrap();
                let extensions = &schema.schema_data.extensions;
                let primary_keys = extensions.get("x-primaryKeys");

                if let Some(primary_keys) = primary_keys {
                    let required = primary_keys
                        .as_array()
                        .unwrap()
                        .iter()
                        .map(|x| x.as_str().unwrap().to_string())
                        .collect();
                    let mut schema_primary_key = ObjectType {required, ..Default::default()};

                    for key in &schema_primary_key.required {
                        let properties = match &schema.schema_kind {
                            SchemaKind::Type(typ) => match typ {
                                Type::String(_) => todo!(),
                                Type::Number(_) => todo!(),
                                Type::Integer(_) => todo!(),
                                Type::Object(schema) => &schema.properties,
                                Type::Array(_) => todo!(),
                                Type::Boolean {  } => todo!(),
                            },
                            SchemaKind::Any(schema) => &schema.properties,
                            _ => todo!(),
                        };

                        schema_primary_key.properties.insert(key.clone(), properties.get(key).unwrap().clone());
                    }

                    let examples: IndexMap<String, ReferenceOr<Example>> = IndexMap::new();
                    let extensions: IndexMap<String, serde_json::Value> = IndexMap::new();
                    let parameter = Parameter::Query {
                        parameter_data: ParameterData {
                            name: "primaryKey".to_string(),
                            required: true,
                            format: ParameterSchemaOrContent::Schema(ReferenceOr::Item(Schema {
                                schema_kind: SchemaKind::Type(Type::Object(schema_primary_key)),
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

                if methods_have_parameters[i] && components.parameters.get(schema_name).is_some() {
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
        //println!("[OpenAPI.get_schema_from_schemas({reference})] : {}", schema_name);
        let schema = self.components.as_ref().unwrap().schemas.get(&schema_name)?;

        return match schema {
            ReferenceOr::Item(schema) => Some(schema),
            _ => None,
        };
    }

    fn get_schema_from_request_bodies(&self, schema_name: &str, may_be_array: bool) -> Option<&Schema> {
        let schema_name = OpenAPI::get_schema_name_from_ref(schema_name);
        let request_body_object = self.components.as_ref().unwrap().request_bodies.get(&schema_name)?.as_item()?;

        for (_, media_type_object) in &request_body_object.content {
            match media_type_object.schema.as_ref()? {
                ReferenceOr::Item(schema) => {
//                    if media_type_object.schema.Properties.is_some() {
                        return Some(schema)
//                    }
                },
                ReferenceOr::Reference { reference } => match self.get_schema_from_ref(reference, may_be_array) {
                    Ok(schema) => return Some(schema),
                    Err(_) => return None,
                },
            }
        }

        None
    }

    fn get_schema_from_responses(&self, schema_name: &str, may_be_array: bool) -> Option<&Schema> {
        let openapi = self;
        let schema_name = &OpenAPI::get_schema_name_from_ref(schema_name);
        let responses = &openapi.components.as_ref().unwrap().responses;
        //println!("[OpenAPI.get_schema_from_responses({}, {})] : {:?}", schema_name, may_be_array, responses);

        let response_object = match responses.get(schema_name) {
            Some(response_object) => response_object.as_item().unwrap(),
            None => return None,
        };

        for (_, media_type_object) in &response_object.content {
            match media_type_object.schema.as_ref().unwrap() {
                ReferenceOr::Reference { reference } => {
                    return Some(openapi.get_schema_from_ref(reference, may_be_array).unwrap())
                },
                ReferenceOr::Item(schema) => {
                    match &schema.schema_kind {
                        SchemaKind::Type(typ) => {
                            match typ {
                                Type::Array(array) => {
                                    if may_be_array {
                                        return Some(schema);
                                    }
        
                                    match &array.items {
                                        Some(schema) => match schema {
                                            ReferenceOr::Reference { reference } => return Some(self.get_schema_from_ref(reference, may_be_array).unwrap()),
                                            ReferenceOr::Item(schema) => return Some(schema.as_ref()),
                                        },
                                        None => todo!(),
                                    };
                                },
                                _ => todo!(),
                            }
                        },
                        SchemaKind::Any(array) => {
                            if may_be_array {
                                return Some(schema);
                            }

                            match &array.items {
                                Some(schema) => match schema {
                                    ReferenceOr::Reference { reference } => return Some(self.get_schema_from_ref(reference, may_be_array).unwrap()),
                                    ReferenceOr::Item(schema) => return Some(schema.as_ref()),
                                },
                                None => todo!(),
                            };
                        },
                        _ => todo!(),
                    }
                }
            }
        }

        None
    }

    fn get_schema_from_ref(&self, reference: &str, may_be_array: bool) -> Result<&Schema, Error> {
        let openapi = self;
        let schema_name = OpenAPI::get_schema_name_from_ref(reference);
        //println!("[OpenAPI.get_schema_from_ref({reference})]");

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
                format!("[OpenAPI.get_schema_from_parameters] don't find schema from {}", reference),
            ));
        };

        match schema {
            ReferenceOr::Reference { reference } => return self.get_schema_from_ref(reference, may_be_array),
            ReferenceOr::Item(schema) => match &schema.schema_kind {
                SchemaKind::Type(typ) => {
                    match typ {
                        Type::Object(_) => Ok(&schema),
                        Type::String(_) => todo!(),
                        Type::Number(_) => todo!(),
                        Type::Integer(_) => todo!(),
                        Type::Array(array) => {
                            if may_be_array {
                                return Ok(schema);
                            }

                            match &array.items {
                                Some(schema) => match schema {
                                    ReferenceOr::Reference { reference } => self.get_schema_from_ref(reference, may_be_array),
                                    ReferenceOr::Item(schema) => Ok(schema),
                                },
                                None => todo!(),
                            }
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

        Err(Error::new("Not found".to_string()))
    }

    fn get_schema_from_operation_object_parameters<'a>(&'a self, operation_object: &'a Operation, may_be_array: bool) -> Result<&Schema, Error> {
        for parameter_object in &operation_object.parameters {
            match &parameter_object {
                ReferenceOr::Reference { reference } => {
                    let schema = self.get_schema_from_ref(reference, may_be_array);
                    println!("[OpenAPI.get_schema_from_operation_object_parameters()] : {:?}", schema);
                    return schema;
                },
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
                                            Type::Object(_) => {
                                                println!("[OpenAPI.get_schema_from_operation_object_parameters()] : {:?}", schema);
                                                return Ok(schema);
                                            },
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

        Err(Error::new(format!("[OpenAPI.get_schema_from_operation_object_parameters] don't find schema parameter from {:?}", operation_object)))
    }

    fn get_schema_from_parameters(&self, path: &str, method: &str, may_be_array: bool) -> Result<&Schema, Error> {
        if let Some(path_item_object) = self.paths.paths.get(path) {
            let path_item_object = match path_item_object {
                ReferenceOr::Reference { reference: _ } => todo!(),
                ReferenceOr::Item(path_item_object) => {
                    path_item_object
                },
            };

            if let Some((_, operation_object)) = path_item_object.iter().find(|x| x.0 == method) {
                return self.get_schema_from_operation_object_parameters(operation_object, may_be_array);
            }
        }

        Err(Error::new(format!("[OpenAPI.get_schema_from_parameters] don't find schema parameter from {}", path)))
    }

    fn get_schema(&self, path :&str, method :&str, schema_place :&SchemaPlace, may_be_array: bool) -> Result<&Schema, Error> {
        fn get_schema_from_content<'a>(openapi: &'a OpenAPI, content :&'a Content, may_be_array: bool) -> Result<&'a Schema, Error> {
            for (_, media_type_object) in content {
                match media_type_object.schema.as_ref().unwrap() {
                    ReferenceOr::Reference { reference } => {
                        return openapi.get_schema_from_ref(reference, may_be_array);
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

            Err(Error::new(format!("Not found")))
        }

        if let Some(path_item_object) = self.paths.paths.get(path) {
            let path_item_object = match path_item_object {
                ReferenceOr::Reference { reference: _ } => todo!(),
                ReferenceOr::Item(path_item_object) => {
                    path_item_object
                },
            };

            if let Some((_, operation_object)) = path_item_object.iter().find(|x| x.0 == method) {
                match schema_place {
                    SchemaPlace::Request => {
                        if let Some(request_object) = &operation_object.request_body {
                            match request_object {
                                ReferenceOr::Item(request_object) => return get_schema_from_content(self, &request_object.content, may_be_array),
                                ReferenceOr::Reference { reference } => {
                                    if let Some(schema) = self.get_schema_from_request_bodies(reference, may_be_array) {
                                        return Ok(schema);
                                    } else {
                                        return Err(Error::new(format!("[get_schema({}, {}, {:?}, {})] : get_schema_from_requests not found schema {} from requests. operation object : {:?}", path, method, schema_place, may_be_array, reference, operation_object)));
                                    }
                                },
                            };
                        } else {
                            return Err(Error::new(format!("Not found reference object from status code 200. operation object : {:?}", operation_object)));
                        }
                    },
                    SchemaPlace::Response => {
                        if let Some(response_object) = operation_object.responses.responses.get(&StatusCode::Code(200)) {
                            match response_object {
                                ReferenceOr::Item(response_object) => return get_schema_from_content(self, &response_object.content, may_be_array),
                                ReferenceOr::Reference { reference } => {
                                    if let Some(schema) = self.get_schema_from_responses(reference, may_be_array) {
                                        return Ok(schema);
                                    } else {
                                        return Err(Error::new(format!("[get_schema({}, {}, {:?}, {})] : get_schema_from_responses not found schema {} from responses. operation object : {:?}", path, method, schema_place, may_be_array, reference, operation_object)));
                                    }
                                },
                            };
                        } else {
                            return Err(Error::new(format!("Not found reference object from status code 200. operation object : {:?}", operation_object)));
                        }
                    },
                    SchemaPlace::Parameter => {
                        return self.get_schema_from_operation_object_parameters(operation_object, may_be_array);
                    },
                    SchemaPlace::Schemas => {
                        return Ok(self.get_schema_from_schemas(path).unwrap());
                    },
                }
            } else {
                return Err(Error::new(format!("[OpenAPI.get_response_schema] missing OperationObject 1 {} {}", path, method)));
            }
        } else {
            return Err(Error::new(format!("[OpenAPI.get_response_schema] missing PathItemObject 2 {}", path)));
        }
    }

    fn get_schema_name(&self, path: &str, method: &str, may_be_array: bool) -> Result<String, Error> {
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
                    ReferenceOr::Reference { reference } => self.get_schema_from_ref(reference, may_be_array).unwrap(),
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
                        Type::Object(_) => {
                            let schema_name = path[1..].to_string().to_case(Case::Camel);
                            return Ok(schema_name)
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

        Err(Error::new("NotFound".to_string()))
    }

    fn get_properties_from_schema<'a>(&'a self, schema :&'a Schema) -> Option<&'a IndexMap<String, ReferenceOr<Box<Schema>>>> {
        match &schema.schema_kind {
            SchemaKind::Type(typ) => match typ {
                Type::Object(object) => Some(&object.properties),
                Type::Array(array) => {
                    if let Some(schema) = &array.items {
                        match schema {
                            ReferenceOr::Reference { reference } => {
                                let schema = self.get_schema_from_ref(reference, false).unwrap();
                                self.get_properties_from_schema(schema)
                            },
                            ReferenceOr::Item(schema) => self.get_properties_from_schema(schema),
                        }
                    } else {
                        None
                    }
                },
                _ => None,
            },
            SchemaKind::Any(any) => Some(&any.properties),
            _ => None,
        }
    }

    fn get_properties_from_schema_name<'a>(&'a self, parent_name: &Option<String>, schema_name :&str, schema_place :&SchemaPlace) -> Option<&'a IndexMap<String, ReferenceOr<Box<Schema>>>> {
        let main_schema_name = if let Some(parent_name) = parent_name {
            parent_name
        } else {
            schema_name
        };

        let schema = match schema_place {
            SchemaPlace::Request => self.get_schema_from_request_bodies(main_schema_name, false)?,
            SchemaPlace::Response => self.get_schema_from_responses(main_schema_name, false)?,
            SchemaPlace::Schemas => self.get_schema_from_schemas(main_schema_name)?,
            SchemaPlace::Parameter => todo!(),
        };

        let schema = if parent_name.is_some() {
            let Some(schema) = self.get_property_from_schema(schema, schema_name) else {
                return None;
            };
            
            schema
        } else {
            schema
        };

        self.get_properties_from_schema(schema)
    }

    fn get_property_from_schema<'a>(&'a self, schema :&'a Schema, property_name :&str) -> Option<&'a Schema> {
        let properties = self.get_properties_from_schema(schema)?;

        if let Some(value) = properties.get(property_name) {
            match value {
                ReferenceOr::Item(item) => return Some(item),
                ReferenceOr::Reference { reference } => match self.get_schema_from_ref(reference, false) {
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
        let schema = self.get_schema_from_request_bodies(schema_name, false)?;
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

    fn get_property_mut<'a>(&'a mut self, schema_name: &'a str, field_name: &'a str) -> Option<&'a mut Box<Schema>> {
        if let Some(components) = self.components.as_mut() {
          if let Some(schema)  = components.schemas.get_mut(schema_name) {
            match schema {
              ReferenceOr::Reference { reference: _ } => todo!(),
              ReferenceOr::Item(schema) => {
                match &mut schema.schema_kind {
                  SchemaKind::Type(schema) => {
                    match schema {
                        Type::String(_) => todo!(),
                        Type::Number(_) => todo!(),
                        Type::Integer(_) => todo!(),
                        Type::Object(schema) => {
                          if let Some(field) = schema.properties.get_mut(field_name) {
                            match field {
                              ReferenceOr::Reference { reference: _ } => todo!(),
                              ReferenceOr::Item(field) => Some(field),
                            }
                          } else {
                            None
                          }
                        },
                        Type::Array(_) => todo!(),
                        Type::Boolean {  } => todo!(),
                    }
                  },
                  SchemaKind::OneOf { one_of: _ } => todo!(),
                  SchemaKind::AllOf { all_of: _ } => todo!(),
                  SchemaKind::AnyOf { any_of: _ } => todo!(),
                  SchemaKind::Not { not: _ } => todo!(),
                  SchemaKind::Any(_) => todo!(),
                }
              },
            }
          } else {
            None
          }
        } else {
          None
        }
    }

    fn get_property_from(&self, path :&str, method :&str, schema_place :&SchemaPlace, may_be_array: bool, property_name :&str) -> Option<&Schema> {
        let schema = self.get_schema(path, method, schema_place, may_be_array).unwrap();
        self.get_property_from_schema(schema, property_name)
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
    fn get_dependencies(&self, schema_name_or_ref: &str, list: &mut Vec<String>) {
        fn process_dependency(openapi :&OpenAPI, schema_ref: &str, list: &mut Vec<String>) {
            if list.contains(&schema_ref.to_string()) == false {
                list.push(schema_ref.to_string());
                openapi.get_dependencies(schema_ref, list);
            }
        }

        fn process_dependencies(openapi :&OpenAPI, properties :&IndexMap<String, ReferenceOr<Box<Schema>>>, list: &mut Vec<String>) {
            for (_, field) in properties {
                match field {
                    ReferenceOr::Reference { reference } => process_dependency(openapi, reference, list),
                    ReferenceOr::Item(schema) => match &schema.schema_kind {
                        SchemaKind::Type(typ) => match typ {
                            Type::Object(object_type) => process_dependencies(openapi, &object_type.properties, list),
                            Type::Array(array) => match &array.items.as_ref().unwrap() {
                                ReferenceOr::Reference { reference } => process_dependency(openapi, reference, list),
                                ReferenceOr::Item(schema) => {
                                    if let Some(properties) = openapi.get_properties_from_schema(schema) {
                                        process_dependencies(openapi, properties, list);
                                    }
                                },
                            },
                            _ => continue,
                        },
                        _ => todo!(),
                    },
                }
            }
        }

        if let Some(properties) = self.get_properties_from_schema_name(&None, schema_name_or_ref, &SchemaPlace::Request) {
            process_dependencies(self, properties, list);
        }

        if let Some(properties) = self.get_properties_from_schema_name(&None, schema_name_or_ref, &SchemaPlace::Response) {
            process_dependencies(self, properties, list);
        }
    }

	fn get_dependents(&self, schema_name_target: &str, only_in_document :bool) -> Vec<Dependent> {
		fn process_properties(openapi :&OpenAPI, properties: &IndexMap<String, ReferenceOr<Box<Schema>>>, schema_name: &str, schema_name_target: &str, only_in_document: bool, list: &mut Vec<Dependent>) {
			for (field_name, field) in properties {
                let field = match field {
                    ReferenceOr::Reference { reference } => openapi.get_schema_from_ref(reference, false).unwrap(),
                    ReferenceOr::Item(schema) => schema,
                };

                let reference = if let Some(reference) = field.schema_data.extensions.get("x-$ref") {
                    reference.as_str().unwrap()
                } else {
                    continue;
                };
        
                if reference == schema_name_target || OpenAPI::get_schema_name_from_ref(reference) == schema_name_target {
                    if only_in_document != true || openapi.get_properties_from_schema(field).is_some() {
                        if list.iter().find(|&item| item.schema == schema_name && &item.field == field_name).is_none() {
                            list.push(Dependent{schema: schema_name.to_string(), field: field_name.clone()});
                        }
                    }
                }
			}
		}

		//let schema_name_target = self.get_schema_name_from_ref(schema_name_target);
		let mut list = vec![];
        let components = &self.components.as_ref().unwrap();

		for (schema_name, _) in &components.request_bodies {
            //let schema_name = schema_name.to_case(Case::Snake);

            if let Some(properties) = self.get_properties_from_schema_name(&None, &schema_name, &SchemaPlace::Request) {
				process_properties(self, properties, &schema_name, schema_name_target, only_in_document, &mut list);
            }
		}

		list
	}

    // (service, (service.field|foreign_table_name)
    fn get_foreign_key_description(&self, schema :&str, field_name: &str) -> Result<Option<ForeignKeyDescription>, Error> {
        let field = self.get_property(schema, field_name);

        if field.is_none() {
            println!("[openapi.get_foreign_key_description({}, {})] trace : missing property in schema", schema, field_name);
            return Ok(None);
        }

        let reference = field.unwrap().schema_data.extensions.get("x-$ref");

        if reference.is_none() {
            println!("[openapi.get_foreign_key_description({}, {})] : trace : missing x-$ref \n{:?}", schema, field_name, field);
            return Ok(None);
        }

        let reference = reference.unwrap().as_str().unwrap();
        let service_ref = self.get_schema_from_schemas(reference);

        if service_ref.is_none() {
            return Err(Error::new(format!("Don't found schema {}", reference)));
        }

        let mut ret = ForeignKeyDescription{
            schema_ref: OpenAPI::get_schema_name_from_ref(reference), ..ForeignKeyDescription::default()
        };

        let primary_keys = if let Some(primary_keys) = service_ref.unwrap().schema_data.extensions.get("x-primaryKeys") {
            let array = primary_keys.as_array().unwrap();
            array.iter().map(|primary_key| primary_key.as_str().unwrap().to_string()).collect::<Vec<String>>()
        } else {
            return Ok(None);
        };

        if primary_keys.len() == 1 {
            ret.fields_ref.insert(primary_keys.get(0).unwrap().clone(), field_name.to_string());
        } else if primary_keys.len() > 1 {
            for field_ref in &primary_keys {
                let property = self.get_property(reference, &field_ref);

                if property.is_some() {
                    if field_ref == "id" {
                        ret.fields_ref.insert(field_ref.clone(), field_name.to_string());
                    } else {
                        ret.fields_ref.insert(field_ref.clone(), field_ref.clone());
                    }
                }
            }
    
            if ret.fields_ref.len() != primary_keys.len() {
                return Err(Error::new(format!("[OpenAPI.getForeignKeyDescription({}, {})] : don't full fields key {:?} : {:?}", schema, field_name, primary_keys, ret.fields_ref)));
            }
        }

        Ok(Some(ret))
    }

	fn get_foreign_key(&self, schema: &str, property_name: &str, obj: &Value) -> Result<Option<Value>, Error> {
        if let Some(foreign_key_description) = self.get_foreign_key_description(schema, property_name)? {
            let mut key = json!({});

            for (field_ref, field_map) in &foreign_key_description.fields_ref {
                key[field_map] = obj[field_ref].clone();
            }
    
            let key = self.copy_fields(&format!("/{}", schema.to_case(Case::Snake)), "get", &SchemaPlace::Response, false, &key, true, false, false)?;
            Ok(Some(key))
        } else {
            Ok(None)
        }
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
                schema: foreign_key_description.schema_ref, 
                primary_key: key, 
                valid: true, 
                //is_unique_key: foreign_key_description.is_unique_key
            };

            for (field_ref, field_name_map) in &foreign_key_description.fields_ref {
                if field_name_map.starts_with("*") {
                    ret.primary_key[field_ref] = Value::String(field_name_map[1..].to_string());
                } else {
                    if let Some(value) = openapi.get_value_from_schema(schema, field_name_map, obj) {
                        if value.is_null() {
                            ret.valid = false;
                        } else {
                            ret.primary_key[field_ref] = value.clone();
                        }
                    } else {
                        ret.valid = false
                    }
                }
            }

            Ok(Some(ret))
        }

        let schema_name = OpenAPI::get_schema_name_from_ref(&schema_name);

        if let Some(schema) = self.get_schema_from_request_bodies(&schema_name, false) {
            return process(self, schema, &schema_name, field_name, obj);
        }

        if let Some(schema) = self.get_schema_from_schemas(&schema_name) {
            return process(self, schema, &schema_name, field_name, obj);
        }

        Err(Error::new(format!("[OpenAPI.get_primary_key_foreign({}, {})] : don't find schema.", schema_name, field_name)))
    }

}
