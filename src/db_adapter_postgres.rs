use std::{io::{Error, ErrorKind}, sync::{Arc}, collections::HashMap};

use convert_case::Casing;
use indexmap::IndexMap;
use openapiv3::{OpenAPI, Schema, ReferenceOr};
use serde_json::{Value, Number, json};
use tokio_postgres::{NoTls, Client, Row, types::{Type, ToSql}};

use crate::{entity_manager::EntityManager, openapi::{RufsOpenAPI, FillOpenAPIOptions, ForeignKey}};

/*
type DbConfig struct {
	driverName             string
	host                   string
	port                   int
	database               string
	user                   string
	password               string
	connectionString       string
	limitQuery             int
	limitQueryExceptions   []string
	requestBodyContentType string
}

type DbClientSql struct {
	dbConfig                   *DbConfig
	openapi                    *OpenApi
	client                     *sql.DB
	sqlTypes                   []string
	rufsTypes                  []string
}
*/


#[derive(Clone)]
struct DbConfig {
	driver_name: String,
	limit_query: usize,
	limit_query_exceptions: Vec<String>,
}

impl Default for DbConfig {
    fn default() -> Self {
        Self { driver_name: Default::default(), limit_query: 1000, limit_query_exceptions: Default::default() }
    }
}

#[derive(Clone,Default)]
pub struct DbAdapterPostgres<'a> {
    pub openapi    : Option<&'a OpenAPI>,
	db_config: DbConfig,
	alias_map: HashMap<String, String>,
	alias_map_external_to_internal :HashMap<String, String>,
	missing_primary_keys: HashMap<String, Vec<String>>,
	missing_foreign_keys: HashMap<String, Vec<ForeignKey>>,
    client: Option<Arc<Client>>,
    //client: Option<Arc<RwLock<Client>>>,
}

impl DbAdapterPostgres<'_> {
    fn get_json(&self, row: &Row) -> Value {
        let mut obj = json!({});

        for idx in 0..row.len() {
            let column = &row.columns()[idx];
            let name = column.name();
            let typ = column.type_();

            let value : Value = match *typ {
                Type::VARCHAR => {
					if let Some(value) = row.get(idx) {
						Value::String(value)
					} else {
						Value::Null
					}
				},
                Type::INT4 => {
					if let Some(value) = row.get::<_, Option<i32>>(idx) {
						Value::Number(Number::from(value))
					} else {
						Value::Null
					}
				},
                Type::INT8 => {
					if let Some(value) = row.get::<usize, Option<i64>>(idx) {
						Value::Number(Number::from(value))
					} else {
						Value::Null
					}
				},
                Type::JSONB => 
				{
					row.get(idx)
				},
                Type::JSONB_ARRAY => {
                    let list = row.get::<_, Vec<Value>>(idx);
                    Value::Array(list)
                },
                _ => row.get(idx)
            };

            obj[name.to_case(convert_case::Case::Camel)] = value;
        }

        obj
    }

    fn get_json_list(&self, rows: &Vec<Row>) -> Vec<Value> {
        let mut list = vec![];

        for row in rows {
            list.push(self.get_json(row));
        }

        list
    }

    pub async fn connect(&mut self, uri :&str) -> Result<(), Error> {
        println!("[DbAdapterPostgres] connect({})", uri);
        let (client, connection) = tokio_postgres::connect(uri, NoTls).await.unwrap();

        tokio::spawn(async move {
            if let Err(e) = connection.await {
                eprintln!("connection error: {}", e);
            }
        });

        //let client = RwLock::new(client);
        let client = Arc::new(client);
        self.client = Some(client);
        Ok(())
    }

    fn build_query<'a>(&self, query_params:&'a Value, params :&mut Vec<&'a (dyn ToSql + Sync)>, order_by :&Vec<String>) -> String {
		fn build_conditions<'a> (query_params:&'a Value, params: &mut Vec<&'a (dyn ToSql + Sync)>, operator:&str, conditions : &mut Vec<String>) {
			let mut count = 1;

			for (field_name, field) in query_params.as_object().unwrap() {
				let field_name = field_name.to_case(convert_case::Case::Snake);
				let param_id = format!("${}", count);
				count += 1;

				match field {
					Value::Null => conditions.push(format!("{} {} NULL", field_name, operator)),
					Value::Bool(value) => conditions.push(format!("{} {} {}", field_name, operator, value)),
					Value::Number(value) => if value.is_i64() {
						conditions.push(format!("{} {} {}", field_name, operator, value.as_i64().unwrap()));
					} else if value.is_u64() {
						conditions.push(format!("{} {} {}", field_name, operator, value.as_u64().unwrap()));
					} else if value.is_f64() {
						conditions.push(format!("{} {} {}", field_name, operator, value.as_f64().unwrap()));
					},
					Value::Array(_) => conditions.push(format!("{} {} ANY ({})", field_name, operator, param_id)),
					_ => conditions.push(format!("{} {} {}", field_name, operator, param_id)),
				}

				match field {
					Value::String(value) => params.push(value),
					Value::Array(value) => params.push(value),
					Value::Object(_) => params.push(field),
					_ => count -= 1,
				}
			}
		}

		let mut conditions: Vec<String> = vec![];

		if query_params.is_object() {
			let filter = &query_params["filter"];
			let filter_range_min = &query_params["filterRangeMin"];
			let filter_range_max = &query_params["filterRangeMax"];
	
			if !filter.is_null() || !filter_range_min.is_null() || !filter_range_max.is_null() {
				if !filter.is_null() {
					build_conditions(filter, params, "=", &mut conditions)
				}
				if !filter_range_min.is_null() {
					build_conditions(filter_range_min, params, ">", &mut conditions)
				}
				if !filter_range_max.is_null() {
					build_conditions(filter_range_max, params, "<", &mut conditions)
				}
			} else if query_params.as_object().iter().len() > 0 {
				build_conditions(query_params, params, "=", &mut conditions)
			}
		}

		let str = if conditions.len() > 0 {
			format!(" WHERE {}", conditions.join(" AND "))
		} else {
			"".to_string()
		};

		if order_by.len() > 0 {
			let mut order_by_internal: Vec<String> = vec![];

			for field_name in order_by {
				let (field_name, extra) = if let Some(pos) = field_name.find(" ") {
					(field_name[0..pos].to_string(), field_name[pos..].to_string())
				} else {
					(field_name.to_string(), "".to_string())
				};

				order_by_internal.push(format!("{} {}", field_name.to_case(convert_case::Case::Snake), extra));
			}

			format!("{} ORDER BY {}", str, order_by_internal.join(","))
		} else {
			str
		}
    }

	async fn query(&self, sql: &str, params: &[&(dyn ToSql + Sync)]) -> Vec<Value> {
		let list = self.client.as_ref().unwrap().query(sql, params).await.unwrap();
		self.get_json_list(&list)
	}

}

#[tide::utils::async_trait]
impl EntityManager for DbAdapterPostgres<'_> {
    async fn insert(&self, _openapi: &OpenAPI, schema_name :&str, obj :&Value) -> Result<Value, Error> {
        println!("[DbAdapterPostgres.find({}, {})]", schema_name, obj.to_string());
		let table_name = schema_name.to_case(convert_case::Case::Snake);
		let mut params: Vec<&(dyn ToSql + Sync)> = vec![];
		let mut str_fields = vec![];
		let mut str_values = vec![];
		let mut count = 1;

		for (field_name, field) in obj.as_object().unwrap() {
			str_fields.push(field_name.to_case(convert_case::Case::Snake));

			match field {
				Value::Null => str_values.push("NULL".to_string()),
				Value::Bool(value) => str_values.push(value.to_string()),
				Value::Number(value) => if value.is_i64() {
					str_values.push(value.as_i64().unwrap().to_string());
				} else if value.is_u64() {
					str_values.push(value.as_u64().unwrap().to_string());
				} else if value.is_f64() {
					str_values.push(value.as_f64().unwrap().to_string());
				},
				Value::String(value) => {
					str_values.push(format!("${}", count));
					params.push(value);
					count += 1;
				},
				Value::Array(value) => {
					str_values.push(format!("${}", count));
					params.push(value);
					count += 1;
				},
				Value::Object(_) => {
					str_values.push(format!("${}", count));
					params.push(field);
					count += 1;
				},
			}
		}

		let sql = format!("INSERT INTO {} ({}) VALUES ({}) RETURNING *", table_name, str_fields.join(","), str_values.join(","));
		let params = params.as_slice();
		let list = self.client.as_ref().unwrap().query(&sql, params).await.unwrap();
		return Ok(self.get_json_list(&list).get(0).unwrap().clone());
	}

	async fn find(&self, openapi: &OpenAPI, schema_name: &str, query_params: &Value, order_by: &Vec<String>) -> Vec<Value> {
		let table_name = schema_name.to_case(convert_case::Case::Snake);
		let mut params = vec![];
		let sql_query = self.build_query(query_params, &mut params, order_by);
		let properties = openapi.get_properties_from_schema_name(schema_name).unwrap();
		let mut count = 0;
		let mut names = vec![];

		for (field_name, property) in properties {
			match property {
				openapiv3::ReferenceOr::Reference { reference } => {
					println!("{} -> {}", field_name, reference);
				},
				openapiv3::ReferenceOr::Item(property) => {
					if let Some(internal_name) = property.schema_data.extensions.get("x-internalName") {
						count += 1;
						names.push(format!("{} as {}", internal_name.as_str().unwrap().to_case(convert_case::Case::Snake), field_name.to_case(convert_case::Case::Snake)));
						continue;
					}
				},
			}

			names.push(field_name.to_case(convert_case::Case::Snake));
		}

		let fields_out = if count > 0 {
			names.join(",")
		} else {
			"*".to_string()
		};

		let mut sql_first = "".to_string();
		let mut sql_limit = "".to_string();

		if self.db_config.limit_query_exceptions.contains(&table_name) == false {
			if self.db_config.driver_name == "firebird" {
				sql_first = format!("FIRST {}", self.db_config.limit_query);
			} else {
				sql_limit = format!("LIMIT {}", self.db_config.limit_query);
			}
		}

		let sql = format!("SELECT {} {} FROM {} {} {}", sql_first, fields_out, table_name, sql_query, sql_limit);
		let params = params.as_slice();
		self.query(&sql, params).await
	}

	async fn find_one(&self, openapi: &OpenAPI, table: &str, key: &Value) -> Option<Box<Value>> {
		println!("[DbAdapterPostgres.find_one({}, {})]", table, key);
		let list = self.find(openapi, table, key, &vec![]).await;

		if list.len() == 0 {
			None
		} else {
			if list.len() > 1 {
				println!("[DbAdapterPostgres.find_one({}, {})] Error : expected one, found {} registers.", table, key, list.len());
			}

			Some(Box::new(list.get(0).unwrap().clone()))
		}
	}

	async fn update(&self, _openapi: &OpenAPI, schema_name :&str, query_params :&Value, obj :&Value) -> Result<Value, Error> {
        println!("[DbAdapterPostgres.update({}, {})]", schema_name, obj.to_string());
		let table_name = schema_name.to_case(convert_case::Case::Snake);
		let mut params: Vec<&(dyn ToSql + Sync)> = vec![];
		let mut str_values = vec![];
		let mut count = 1;

		for (field_name, field) in obj.as_object().unwrap() {
			match field {
				Value::Null => str_values.push(format!("{}=NULL", field_name)),
				Value::Bool(value) => str_values.push(format!("{}={}", field_name, value)),
				Value::Number(value) => if value.is_i64() {
					str_values.push(format!("{}={}", field_name, value.as_i64().unwrap()));
				} else if value.is_u64() {
					str_values.push(format!("{}={}", field_name, value.as_u64().unwrap()));
				} else if value.is_f64() {
					str_values.push(format!("{}={}", field_name, value.as_f64().unwrap()));
				},
				Value::String(value) => {
					str_values.push(format!("{}=${}", field_name, count));
					params.push(value);
					count += 1;
				},
				Value::Array(value) => {
					str_values.push(format!("{}=${}", field_name, count));
					params.push(value);
					count += 1;
				},
				Value::Object(_) => {
					str_values.push(format!("{}=${}", field_name, count));
					params.push(field);
					count += 1;
				},
			}
		}

		let sql_query = self.build_query(query_params, &mut params, &vec![]);
		let sql = format!("UPDATE {} SET {} {} RETURNING *", table_name, str_values.join(","), sql_query);
		let params = params.as_slice();
		let list = self.client.as_ref().unwrap().query(&sql, params).await.unwrap();
		return Ok(self.get_json_list(&list).get(0).unwrap().clone());
	}

	async fn delete_one(&self, _openapi: &OpenAPI, schema_name: &str, query_params: &Value) -> Result<(), Error> {
		println!("[DbAdapterPostgres.delete_one({}, {})]", schema_name, query_params);
		let table_name = schema_name.to_case(convert_case::Case::Snake);
		let mut params: Vec<&(dyn ToSql + Sync)> = vec![];
		let sql_query = self.build_query(query_params, &mut params, &vec![]);
		let sql = format!("DELETE FROM {} WHERE {}", table_name, sql_query);
		let params = params.as_slice();
		let _count = self.client.as_ref().unwrap().execute(&sql, params).await.unwrap();
		Ok(())
	}
/*
	async fn update_open_api(&self, options :&FillOpenAPIOptions) -> Result<(), Error> {
		fn get_field_name(adapter :&DbAdapterPostgres, column_name :&str, field :Option<&ReferenceOr<Schema>>) -> String {
			let field_name = column_name.to_case(convert_case::Case::Camel);
			let field_name_lower_case = field_name.to_lowercase();

			for (alias_map_name, value) in adapter.alias_map {
				if alias_map_name.to_lowercase() == field_name_lower_case {
					if let Some(field) = field {
						field.set_extension("internalName", Value::String(field_name));

						if value.len() > 0 {
							adapter.alias_map_external_to_internal.insert(value, field_name);
						}
					}

					if value.len() > 0 {
						field_name = value;
					} else {
						field_name = alias_map_name;
					}

					break;
				}
			}

			return field_name;
		}

		fn set_ref(properties: IndexMap<String, ReferenceOr<Box<Schema>>>, field_name :&str, table_ref :&str) {
			if let Some(field) = properties.get(field_name) {
				field.set_extension("ref", Value::String(format!("#/components/schemas/{}", table_ref)));
			}
		}

		async fn process_constraints(adapter :&DbAdapterPostgres<'_>, schemas :&IndexMap<String, Schema>) -> Result<(), Error> {
			let sql_info_constraints = "SELECT table_name,constraint_name,constraint_type FROM information_schema.table_constraints ORDER BY table_name,constraint_name";
			let sql_info_constraints_fields = "SELECT constraint_name,column_name,ordinal_position FROM information_schema.key_column_usage ORDER BY constraint_name,ordinal_position";
			let sql_info_constraints_fields_ref = "SELECT constraint_name,table_name,column_name FROM information_schema.constraint_column_usage";
			let result = adapter.query(sql_info_constraints, &[]).await;
			let result_fields = adapter.query(sql_info_constraints_fields, &[]).await;
			let result_fields_ref = adapter.query(sql_info_constraints_fields_ref, &[]).await;

			for (schema_name, schema) in schemas {
				let table_name = schema_name.to_case(convert_case::Case::Snake);
				let primary_keys = schema.schema_data.extensions.get_mut("x-primaryKeys").unwrap_or(&mut json!([]));
				let foreign_keys = schema.schema_data.extensions.get_mut("x-foreignKeys").unwrap_or(&mut json!({}));
				let unique_keys = schema.schema_data.extensions.get_mut("x-uniqueKeys").unwrap_or(&mut json!({}));

				let mut object_type = match &schema.schema_kind {
					openapiv3::SchemaKind::Type(typ) => match typ {
						openapiv3::Type::Object(object_type) => object_type,
						_ => todo!()
					},
					_ => todo!()
				};

				for constraint in result {
					if constraint["tableName"].as_str().unwrap().to_lowercase().trim_end() != table_name {
						continue;
					}

					if constraint["constraintName"] == "" {
						continue;
					}

					let constraint_name = constraint["constraintName"].as_str().unwrap().trim_end();
					let name = constraint_name.to_case(convert_case::Case::Camel);
					let mut list : Vec<Value> = vec![];

					for item in result_fields {
						if item["constraintName"].as_str().unwrap().trim_end() == constraint_name {
							list.push(item);
						}
					}

					let mut list_ref : Vec<Value> = vec![];

					for item in result_fields_ref {
						if item["constraintName"].as_str().unwrap().trim_end() == constraint_name {
							list_ref.push(item);
						}
					}

					let constraint_type = constraint["constraintType"].as_str().unwrap().trim_end();

					if constraint_type == "FOREIGN KEY" {
						let mut foreign_key = ForeignKey{fields: vec![], fields_ref: vec![], table_ref: String::new()};

						for item in list {
							foreign_key.fields.push(get_field_name(adapter, item["columnName"].as_str().unwrap(), None));
						}

						for item_ref in list_ref {
							foreign_key.fields_ref.push(get_field_name(adapter, item_ref["columnName"].as_str().unwrap(), None));
							let table_ref = item_ref["tableName"].as_str().unwrap().to_lowercase().to_case(convert_case::Case::Camel);

							if foreign_key.table_ref == "" || foreign_key.table_ref == table_ref {
								foreign_key.table_ref = table_ref;
							}
						}

						if foreign_key.fields.len() != foreign_key.fields_ref.len() {
							continue;
						}

						if foreign_key.fields.len() == 1 {
							set_ref(schema.as_object_type().unwrap().properties, &foreign_key.fields[0], &foreign_key.table_ref);
							continue;
						}

						if foreign_key.fields.len() > 1 && foreign_key.fields.contains(&foreign_key.table_ref) {
							set_ref(schema.as_object_type().unwrap().properties, &foreign_key.table_ref, &foreign_key.table_ref);
						}

						foreign_keys[name] = serde_json::to_value(foreign_key)?;
					} else if constraint_type == "UNIQUE" {
						for item in list {
							let field_name = get_field_name(adapter, item["columnName"].as_str().unwrap(), None);

							if let Some(list) = unique_keys.get_mut(name) {
								list.as_array().unwrap().push(Value::String(field_name));
							} else {
								unique_keys[name] = json!([field_name]);
							}
						}
					} else if constraint_type == "PRIMARY KEY" {
						for item in list {
							let field_name = get_field_name(adapter, item["columnName"].as_str().unwrap(), None);
							let value = Value::String(field_name);

							if let Some(list) = schema.schema_data.extensions.get_mut("x-primaryKeys") {
								if list.as_array().unwrap().contains(&value) == false {
									list.as_array().unwrap().push(value);
								}
							} else {
								schema.schema_data.extensions.insert("x-primaryKeys".to_string(), json!([value]));
							}

							if object_type.required.contains(&field_name) == false {
								object_type.required.push(field_name);
							}
						}
					}
				}

				for (name, foreign_key) in foreign_keys.as_object().unwrap() {
					let foreign_key : ForeignKey = serde_json::from_value(foreign_key.clone()).unwrap();
					let candidates = vec![];

					for field_name in foreign_key.fields {
						if let Some(field) = object_type.properties.get(&field_name) {
							if field.as_item().unwrap().schema_data.extensions.contains_key("x-ref") == false {
								candidates.push(field_name);
							}
						}
					}

					if candidates.len() == 1 {
						set_ref(object_type.properties, &candidates[0], &foreign_key.table_ref);
						foreign_keys.as_object().unwrap().remove(name);
					}
				}

				if let Some(list) = adapter.missing_primary_keys.get(schema_name) {
					for column_name in list {
						let value = Value::String(column_name.to_string());

						if primary_keys.as_array().unwrap().contains(&value) == false {
							primary_keys.as_array().unwrap().push(value);
						}

						if object_type.required.contains(column_name) == false {
							object_type.required.push(column_name.clone());
						}
					}
				}

				if let Some(list) = adapter.missing_foreign_keys.get(schema_name) {
					for foreign_key in list {
						set_ref(object_type.properties, field_name, table_ref);
					}
				}

				if schema.required.len() == 0 {
					println!("[process_columns()] : missing required fields of table {schema_name}");
				}

				schema.schema_data.extensions.insert("x-primaryKeys".to_string(), primary_keys.clone());
				schema.schema_data.extensions.insert("x-uniqueKeys".to_string(), unique_keys.clone());
				schema.schema_data.extensions.insert("x-foreignKeys".to_string(), foreign_keys.clone());
			}

			Ok()
		}

		fn process_columns(adapter :&DbAdapterPostgres, schemas :&mut IndexMap<String, Schema>) -> Result<(), Error> {
			let sql_types = vec!["boolean", "character varying", "character", "integer", "jsonb", "jsonb array", "numeric", "timestamp without time zone", "timestamp with time zone", "time without time zone", "bigint", "smallint", "text", "date", "double precision", "bytea"];
			let rufs_types = vec!["boolean", "string", "string", "integer", "object", "array", "number", "date-time", "date-time", "date-time", "integer", "integer", "string", "date-time", "number", "string"];
			let sql_info_tables = "
			select 
			c.data_type,
			c.udt_name,
			c.table_name,
			c.column_name,
			c.is_nullable,
			c.is_updatable,
			COALESCE(c.numeric_scale, 0) as numeric_scale,
			COALESCE(c.numeric_precision, 0) as numeric_precision,
			COALESCE(c.character_maximum_length, 0) as character_maximum_length,
			COALESCE(c.column_default, '') as column_default,
			COALESCE(c.identity_generation, '') as identity_generation,
			left(COALESCE(pgd.description, ''),100) as description
			from pg_catalog.pg_statio_all_tables as st
			inner join pg_catalog.pg_description pgd on (pgd.objoid=st.relid)
			right outer join information_schema.columns c on (pgd.objsubid=c.ordinal_position and c.table_schema=st.schemaname and c.table_name=st.relname)
			where table_schema = 'public' order by c.table_name,c.ordinal_position
			";
			let rows = adapter.client.query(sql_info_tables);

			for row in rows {
				let rec = adapter.get_map_from_row(rows, None);
				let sql_type = rec["dataType"].trim(" ").to_lower();
				let sql_sub_type = rec["udtName"].trim(" ").to_lower();

				if sql_type == "array" && sql_sub_type == "_jsonb" {
					sql_type = "jsonb array"
				}

				let type_index = adapter.sql_types.index(sql_type);

				if type_index < 0 {
					println!("DbClientPostgres.getTablesInfo().processColumns() : Invalid Database Type : {sql_type}, full rec : {}", rec);
					continue
				}

				let table_name = rec["tableName"].to_case(camel);

				let schema = if let Some(schema) = schemas.get(table_name) {
					schema
				} else {
					schemas.insert(tableName, Schema::new());
					schemas.get(table_name).unwrap();
				};

				let field = Schema{};
				let field_name = get_field_name(rec["columnName"], field);
				field.unique_keys = None;
				field.typ = adapter.rufs_types[type_index]; // LocalDateTime,ZonedDateTime,Date,Time

				if field.typ == "date-time" {
					field.typ = "string";
					field.format = "date-time";
				}

				field.nullable = rec["isNullable"] == "YES" || rec["isNullable"] == 1;    // true,false
				field.Updatable = rec["isUpdatable"] == "YES" || rec["isUpdatable"] == 1; // true,false
				field.scale = rec["numericScale"];                           // > 0 // 3,2,1
				field.precision = rec["numericPrecision"];                   // > 0

				if rec["columnDefault"].is_nome == false {
					field.default = rec["columnDefault"]; // 'pt-br'::character varying
				}
				if rec["description"].is_nome == false {
					field.description = rec["description"];
				}

				if field.nullable != true {
					if schema.required.index(field_name) < 0 {
						schema.required = schema.required.append(field_name);
					}

					field.essential = true;
				}

				if sql_type.has_prefix("character") == true {
					field.max_length = rec["characterMaximumLength"]; // > 0 // 255
				}

				if field.typ == "number" && field.scale == 0 {
					field.typ = "integer";
				}

				if field.default != "" && field.default[0..1] == "'" && field.default.len() > 2 {
					let pos_end = field.default.last_index("'");

					if field.typ == "string" && pos_end > 1 {
						field.default = field.default[1..pos_end];
					} else {
						field.default = "";
					}
				}

				if (field.typ == "integer" || field.typ == "number") && field.default.len() > 0 {
					if let Ok(_) = field.default.parse_float() {
						field.default = "";
					}
				}

				if rec["identityGeneration"].is_some() {
					field.identity_generation = rec["identityGeneration"]
				}
				// SERIAL TYPE
				if field.default.has_prefix("nextval") {
					field.identity_generation = "BY DEFAULT";
				}

				if field.typ == "array" {
					field.items = Schema{};
				}

				schema.properties[field_name] = field;
			}

			Ok(schemas)
		};

		let mut schemas : IndexMap<String, Schema> = IndexMap::new();
		process_columns(self, &schemas);
		process_constraints(&schemas);
		options.schemas = schemas;
		adapter.openapi = openapi;
		openapi.fill_open_api(options);
		Ok()
	}

*/
	/*
fn CreateTable(name:&str, schema *Schema) (sql.Result, error) {
	genSqlColumnDescription := func(fieldName:&str, field *Schema) (string, error) {
		if field.Type == "" {
			if field.IdentityGeneration != "" {
				field.Type = "integer"
			} else {
				field.Type = "string"
			}
		}

		pos := slices.Index(adapter.rufsTypes, field.Type)

		if pos < 0 {
			return "", fmt.Errorf(`[CreateTable(%s).genSqlColumnDescription(%s)] Missing rufsType equivalent of %s`, name, fieldName, field.Type)
		}

		sqlType := adapter.sqlTypes[pos]

		if field.Type == "string" && field.MaxLength > 0 && field.MaxLength < 32 {
			sqlType = "character"
		}

		if field.MaxLength == 0 {
			if field.Type == "string" {
				field.MaxLength = 255
			}
			if field.Type == "number" {
				field.MaxLength = 9
			}
		}

		if field.Type == "number" && field.Scale == 0 {
			field.Scale = 3
		}

		sqlLengthScale := ""

		if field.MaxLength != 0 && field.Scale != 0 {
			sqlLengthScale = fmt.Sprintf(`(%d,%d)`, field.MaxLength, field.Scale)
		} else if field.MaxLength != 0 {
			sqlLengthScale = fmt.Sprintf(`(%d)`, field.MaxLength)
		}

		sqlDefault := ""

		if field.IdentityGeneration != "" {
			sqlDefault = fmt.Sprintf(`GENERATED %s AS IDENTITY`, field.IdentityGeneration)
			sqlType = `int`
		}

		if field.Default != "" {
			if field.Type == "string" {
				sqlDefault = fmt.Sprintf(` DEFAULT '%s'`, field.Default)
			} else {
				sqlDefault = " DEFAULT " + field.Default
			}
		}

		sqlNotNull := ""
		if field.Nullable != true {
			sqlNotNull = "NOT NULL"
		}
		return fmt.Sprintf(`%s %s%s %s %s`, CamelToUnderscore(fieldName), sqlType, sqlLengthScale, sqlDefault, sqlNotNull), None
	}
	// TODO : refatorar função genSqlForeignKey(fieldName, field) para genSqlForeignKey(tableName)
	genSqlForeignKey := func(fieldName:&str, field *Schema) string {
		ref := OpenApiGetSchemaName(field.Ref)
		tableOut := CamelToUnderscore(ref)
		return fmt.Sprintf(`FOREIGN KEY(%s) REFERENCES %s`, CamelToUnderscore(fieldName), tableOut)
	}

	tableBody := ""
	for fieldName, field := range schema.Properties {
		fieldDescription, err := genSqlColumnDescription(fieldName, field)

		if err != nil {
			return nil, err
		}

		tableBody = tableBody + fieldDescription + ", "
	}
	// add foreign keys
	for fieldName, field := range schema.Properties {
		if field.Ref != "" {
			tableBody = tableBody + genSqlForeignKey(fieldName, field) + ", "
		}
	}
	// add primary key
	tableBody = tableBody + `PRIMARY KEY(`
	for _, fieldName := range schema.PrimaryKeys {
		tableBody = tableBody + CamelToUnderscore(fieldName) + `, `
	}
	tableBody = tableBody[:len(tableBody)-2] + `)`
	tableName := CamelToUnderscore(name)
	sql := fmt.Sprintf(`CREATE TABLE %s (%s)`, tableName, tableBody)
	fmt.Printf("entityManager.createTable() : table %s, sql : \n%s\n", name, sql)
	result, err := self.client.Exec(sql)

	if err != nil {
		return nil, err
	}

	err = self.UpdateOpenApi(self.openapi, FillOpenApiOptions{requestBodyContentType: self.dbConfig.requestBodyContentType})

	return result, err
}
*/
}
