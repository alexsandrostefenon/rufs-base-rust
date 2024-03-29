use std::{io::{Error}, sync::{Arc}, collections::HashMap};

use chrono::NaiveDateTime;
use convert_case::Casing;
use indexmap::IndexMap;
use openapiv3::{OpenAPI, Schema, ReferenceOr, ObjectType, SchemaData, SchemaKind, VariantOrUnknownOrEmpty, StringFormat};
use serde::Deserialize;
use serde_json::{Value, Number, json};
#[cfg(not(target_arch = "wasm32"))]
use rust_decimal::{Decimal, prelude::ToPrimitive};
use anyhow::Context;
#[cfg(not(target_arch = "wasm32"))]
use crate::{entity_manager::EntityManager};

#[cfg(not(target_arch = "wasm32"))]
use tokio_postgres::{Client, Row, types::{ToSql}};
#[cfg(not(target_arch = "wasm32"))]
use crate::openapi::{RufsOpenAPI, FillOpenAPIOptions, ForeignKey};

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


#[cfg(not(target_arch = "wasm32"))]
#[derive(Clone)]
struct DbConfig {
	driver_name: String,
	limit_query: usize,
	limit_query_exceptions: Vec<String>,
}

#[cfg(not(target_arch = "wasm32"))]
impl Default for DbConfig {
    fn default() -> Self {
        Self { driver_name: Default::default(), limit_query: 10000, limit_query_exceptions: Default::default() }
    }
}

#[cfg(not(target_arch = "wasm32"))]
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

#[cfg(not(target_arch = "wasm32"))]
impl DbAdapterPostgres<'_> {
    fn get_json(&self, row: &Row, _debug: bool) -> Value {
        let mut obj = json!({});

        for idx in 0..row.len() {
            let column = &row.columns()[idx];
            let name = column.name();
            let typ = column.type_();

            let value : Value = match *typ {
                tokio_postgres::types::Type::VARCHAR | tokio_postgres::types::Type::TEXT | tokio_postgres::types::Type::BPCHAR => {
					if let Some(value) = row.get(idx) {
						Value::String(value)
					} else {
						Value::Null
					}
				},
                tokio_postgres::types::Type::INT4 => {
					if let Some(value) = row.get::<_, Option<i32>>(idx) {
						Value::Number(Number::from(value))
					} else {
						Value::Null
					}
				},
                tokio_postgres::types::Type::INT8 => {
					if let Some(value) = row.get::<usize, Option<i64>>(idx) {
						Value::Number(Number::from(value))
					} else {
						Value::Null
					}
				},
                tokio_postgres::types::Type::TIMESTAMP => {
					if let Some(value) = row.get::<usize, Option<NaiveDateTime>>(idx) {
/*
						let fmt = value.format("%+");
						println!("{}", fmt);
						let str = fmt.to_string();
						println!("{}", str);
						let fmt = value.format("%Y-%m-%dT%H:%M:%S%.f%:z");
						println!("{}", fmt);
						let str = fmt.to_string();
						println!("{}", str);
						let fmt = value.format("%Y-%m-%dT%H:%M:%S%.fZ");
						println!("{}", fmt);
						let str = fmt.to_string();
						println!("{}", str);
						 */
						//let str = format!("{}.000Z", value);
						//2018-05-18 20:08:34
						//2018-05-18T20:08:34
						let str = value.to_string();
						let left = &str[..10];
						let right = &str[11..];
						let str_out = [left, right].join("T");
						Value::String(str_out)
					} else {
						Value::Null
					}
				},
                tokio_postgres::types::Type::NUMERIC => {
					let value : Decimal = row.get(idx);

					if value.scale() == 0 {
						if let Some(value) = value.to_i64() {
							Value::Number(Number::from(value))
						} else {
							Value::Null
						}
					} else {
						if let Some(value) = value.to_f64() {
							Value::Number(Number::from_f64(value).unwrap())
						} else {
							Value::Null
						}
					}
				},
                tokio_postgres::types::Type::JSONB => {
					row.get(idx)
				},
                tokio_postgres::types::Type::JSONB_ARRAY => {
                    let list = row.get::<_, Vec<Value>>(idx);
                    Value::Array(list)
                },
                _ => row.get(idx)
            };

            obj[name.to_case(convert_case::Case::Camel)] = value;
        }

        obj
    }

    fn get_json_list(&self, rows: &Vec<Row>, debug: bool) -> Vec<Value> {
        let mut list = vec![];

        for row in rows {
            list.push(self.get_json(row, debug));
        }

        list
    }

    pub async fn connect(&mut self, uri :&str) -> Result<(), Box<dyn std::error::Error>> {
        println!("[DbAdapterPostgres] connect({})", uri);
        let (client, connection) = tokio_postgres::connect(uri, tokio_postgres::NoTls).await?;

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
		println!("[DbAdapterPostgres.query] {} - {:?}", sql.replace("\n", " "), params);
		
		let list = match self.client.as_ref().unwrap().query(sql, params).await {
			Ok(list) => list,
			Err(err) => {
				println!("[DbAdapterPostgres.query] : {}", err);
				vec![]
			},
		};

		self.get_json_list(&list, false)
	}

}

#[cfg(not(target_arch = "wasm32"))]
#[tide::utils::async_trait]
impl EntityManager for DbAdapterPostgres<'_> {
	async fn exec(&self, sql: &str) -> Result<(), Error> {
		if let Err(error) = self.client.as_ref().unwrap().batch_execute(sql).await {
			Err(Error::new(std::io::ErrorKind::InvalidInput, error.to_string()))
		} else {
			Ok(())
		}
	}

    async fn insert(&self, openapi: &OpenAPI, schema_name :&str, obj :&Value) -> Result<Value, Box<dyn std::error::Error>> {
        println!("[DbAdapterPostgres.find({}, {})]", schema_name, obj.to_string());
		let table_name = schema_name.to_case(convert_case::Case::Snake);
		let mut params: Vec<&(dyn ToSql + Sync)> = vec![];
		let mut str_fields = vec![];
		let mut str_values = vec![];
		let mut count = 1;
		let properties = openapi.get_properties_from_schema_name(&None, schema_name, &crate::openapi::SchemaPlace::Schemas).context(format!("EntityManager.insert({}) : Missing porperties for schema", schema_name))?;

		for (field_name, field) in properties {
			let field = field.as_item().context(format!("EntityManager.insert({}) : field {} must be item, not reference", schema_name, field_name))?;
			let value = obj.as_object().unwrap().get(field_name);
			let value = match value {
				Some(value) => value,
				None => match &field.schema_data.default {
					Some(default) => default,
					None => &Value::Null,
				},
			};

			if value.is_null() && field.schema_data.extensions.get("x-identityGeneration").is_some() {
				continue;
			}

			match value {
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
					match &field.schema_kind {
						SchemaKind::Type(typ) => match typ {
							openapiv3::Type::String(string_type) => {
								match &string_type.format {
									VariantOrUnknownOrEmpty::Item(string_format) => match string_format {
										StringFormat::DateTime => {
											str_values.push(format!("'{}'", value));
										},
										_ => todo!(),
									},
									_ => {
										str_values.push(format!("${}", count));
										params.push(value);
										count += 1;
									},
								}
							},
							_ => todo!()
						},
						_ => todo!()
					}
				},
				Value::Array(value) => {
					str_values.push(format!("${}", count));
					params.push(value);
					count += 1;
				},
				Value::Object(_) => {
					str_values.push(format!("${}", count));
					params.push(value);
					count += 1;
				},
			}

			str_fields.push(field_name.to_case(convert_case::Case::Snake));
		}

		let sql = format!("INSERT INTO {} ({}) VALUES ({}) RETURNING *", table_name, str_fields.join(","), str_values.join(","));
		println!("[DbAdapterPostgres.insert] : {}", sql);
		let params = params.as_slice();
		let list = self.client.as_ref().unwrap().query(&sql, params).await?;
		println!("[DbAdapterPostgres.insert] : returning* = {:?}", list);
		Ok(self.get_json_list(&list, true).get(0).unwrap().clone())
	}

	async fn find(&self, openapi: &OpenAPI, schema_name: &str, query_params: &Value, order_by: &Vec<String>) -> Vec<Value> {
		let table_name = schema_name.to_case(convert_case::Case::Snake);
		let mut params = vec![];
		let sql_query = self.build_query(query_params, &mut params, order_by);
		let properties = openapi.get_properties_from_schema_name(&None, schema_name, &crate::openapi::SchemaPlace::Schemas).unwrap();
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

	async fn update(&self, openapi: &OpenAPI, schema_name :&str, query_params :&Value, obj :&Value) -> Result<Value, Box<dyn std::error::Error>> {
        println!("[DbAdapterPostgres.update({}, {})]", schema_name, obj.to_string());
		let table_name = schema_name.to_case(convert_case::Case::Snake);
		let mut params: Vec<&(dyn ToSql + Sync)> = vec![];
		let mut str_values = vec![];
		let mut count = 1;
		let properties = openapi.get_properties_from_schema_name(&None, schema_name, &crate::openapi::SchemaPlace::Schemas).context(format!("EntityManager.update({}) : Missing porperties for schema", schema_name))?;

		for (field_name, value) in obj.as_object().context(format!("EntityManager.update({}) : value must be json object", schema_name))? {
			let field = properties.get(field_name).context(format!("EntityManager.update({}) : field {} missing in schema definition", schema_name, field_name))?;
			let field = field.as_item().context(format!("EntityManager.insert({}) : field {} must be item, not reference", schema_name, field_name))?;
			let field_name = field_name.to_case(convert_case::Case::Snake);

			match value {
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
					match &field.schema_kind {
						SchemaKind::Type(typ) => match typ {
							openapiv3::Type::String(string_type) => {
								match &string_type.format {
									VariantOrUnknownOrEmpty::Item(string_format) => match string_format {
										StringFormat::DateTime => {
											str_values.push(format!("{}='{}'", field_name, value));
										},
										_ => todo!(),
									},
									_ => {
										str_values.push(format!("{}=${}", field_name, count));
										params.push(value);
										count += 1;
									},
								}
							},
							_ => todo!()
						},
						_ => todo!()
					}
				},
				Value::Array(value) => {
					str_values.push(format!("{}=${}", field_name, count));
					params.push(value);
					count += 1;
				},
				Value::Object(_) => {
					str_values.push(format!("{}=${}", field_name, count));
					params.push(value);
					count += 1;
				},
			}
		}

		let sql_query = self.build_query(query_params, &mut params, &vec![]);
		let sql = format!("UPDATE {} SET {} {} RETURNING *", table_name, str_values.join(","), sql_query);
		println!("[DbAdapterPostgres.update()] : {}", sql);
		let params = params.as_slice();
		let list = self.client.as_ref().unwrap().query(&sql, params).await.unwrap();
		println!("[DbAdapterPostgres.update] : returning* = {:?}", list);
		Ok(self.get_json_list(&list, true).get(0).unwrap().clone())
	}

	async fn delete_one(&self, _openapi: &OpenAPI, schema_name: &str, query_params: &Value) -> Result<(), Error> {
		println!("[DbAdapterPostgres.delete_one({}, {})]", schema_name, query_params);
		let table_name = schema_name.to_case(convert_case::Case::Snake);
		let mut params: Vec<&(dyn ToSql + Sync)> = vec![];
		let sql_query = self.build_query(query_params, &mut params, &vec![]);
		let sql = format!("DELETE FROM {} {}", table_name, sql_query);
		let params = params.as_slice();
		println!("[DbAdapterPostgres.delete_one({})] : {} , {:?}", query_params, sql, params);
		let _count = self.client.as_ref().unwrap().execute(&sql, params).await.unwrap();
		Ok(())
	}

	async fn update_open_api(&mut self, openapi: &mut OpenAPI, options :&mut FillOpenAPIOptions) -> Result<(), Error> {
		fn get_field_name(adapter :&mut DbAdapterPostgres, column_name :&str, schema_data :Option<&mut SchemaData>) -> String {
			let mut field_name = column_name.to_case(convert_case::Case::Camel);
			let field_name_lower_case = field_name.to_lowercase();

			for (alias_map_name, value) in &adapter.alias_map {
				if alias_map_name.to_lowercase() == field_name_lower_case {
					if let Some(schema_data) = schema_data {
						schema_data.extensions.insert("x-internalName".to_string(), Value::String(field_name.clone()));

						if value.len() > 0 {
							adapter.alias_map_external_to_internal.insert(value.clone(), field_name.clone());
						}
					}

					if value.len() > 0 {
						field_name = value.clone();
					} else {
						field_name = alias_map_name.clone();
					}

					break;
				}
			}

			return field_name;
		}

		fn set_ref(properties: &mut IndexMap<String, ReferenceOr<Box<Schema>>>, field_name :&str, table_ref :&str) {
			if let Some(field) = properties.get_mut(field_name) {
				if let ReferenceOr::Item(field) = field {
					field.schema_data.extensions.insert("x-$ref".to_string(), Value::String(format!("#/components/schemas/{}", table_ref)));
				}
			}
		}

		async fn process_constraints(adapter :&mut DbAdapterPostgres<'_>, schemas :&mut IndexMap<String, ReferenceOr<Schema>>) -> Result<(), Error> {
			let sql_info_constraints = "SELECT table_name::text,constraint_name::text,constraint_type::text FROM information_schema.table_constraints ORDER BY table_name,constraint_name";
			let sql_info_constraints_fields = "SELECT constraint_name::text,column_name::text,ordinal_position FROM information_schema.key_column_usage ORDER BY constraint_name,ordinal_position";
			let sql_info_constraints_fields_ref = "SELECT constraint_name::text,table_name::text,column_name::text FROM information_schema.constraint_column_usage";
			let result = &adapter.query(sql_info_constraints, &[]).await;
			let result_fields = &adapter.query(sql_info_constraints_fields, &[]).await;
			let result_fields_ref = &adapter.query(sql_info_constraints_fields_ref, &[]).await;

			for (schema_name, schema) in schemas {
				let schema = if let ReferenceOr::Item(schema) = schema {
					schema
				} else {
					continue;
				};

				let table_name = schema_name.to_case(convert_case::Case::Snake);
				let extensions = &mut schema.schema_data.extensions;

				let mut primary_keys = if let Some(primary_keys) = extensions.get_mut("x-primaryKeys") {
					primary_keys.clone()
				} else {
					json!([])
				};

				let mut foreign_keys = if let Some(foreign_keys) = extensions.get_mut("x-foreignKeys") {
					foreign_keys.clone()
				} else {
					json!({})
				};
				
				let mut unique_keys = if let Some(unique_keys) = extensions.get_mut("x-uniqueKeys") {
					unique_keys.clone()
				} else {
					json!({})
				};

				let schema_kind = &mut schema.schema_kind;

				let object_type = match schema_kind {
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
					let name = &constraint_name.to_case(convert_case::Case::Camel);
					let list = &mut vec![];

					for item in result_fields {
						if item["constraintName"].as_str().unwrap().trim_end() == constraint_name {
							list.push(item.clone());
						}
					}

					let mut list_ref : Vec<Value> = vec![];

					for item in result_fields_ref {
						if item["constraintName"].as_str().unwrap().trim_end() == constraint_name {
							list_ref.push(item.clone());
						}
					}

					let constraint_type = constraint["constraintType"].as_str().unwrap().trim_end();

					if constraint_type == "FOREIGN KEY" {
						if list.len() != list_ref.len() {
							println!("[DbAdapterPostgres.update_open_api.process_constraints.FOREIGN KEY] not same size of lists :\n{:?}\n{:?}", list, list_ref);
							continue;
						}

						let mut foreign_key = ForeignKey::default();

						for i in 0..list.len() {
							let item = &list[i];
							let item_ref = &list_ref[i];
							let field = get_field_name(adapter, item["columnName"].as_str().unwrap(), None);
							let field_ref = get_field_name(adapter, item_ref["columnName"].as_str().unwrap(), None);
							foreign_key.fields.insert(field, field_ref);
							let table_ref = item_ref["tableName"].as_str().unwrap().to_lowercase().to_case(convert_case::Case::Camel);

							if foreign_key.table_ref == "" || foreign_key.table_ref == table_ref {
								foreign_key.table_ref = table_ref;
							} else {
								println!("[DbAdapterPostgres.update_open_api.process_constraints.FOREIGN KEY] not same table_ref :\n{}\n{}", foreign_key.table_ref, table_ref);
							}
						}

						if foreign_key.fields.len() == 1 {
							for (field, _field_ref) in foreign_key.fields {
								set_ref(&mut object_type.properties, &field, &foreign_key.table_ref);
							}

							continue;
						}

						if foreign_key.fields.len() > 1 && foreign_key.fields.contains_key(&foreign_key.table_ref) {
							set_ref(&mut object_type.properties, &foreign_key.table_ref, &foreign_key.table_ref);
						}

						foreign_keys[name] = serde_json::to_value(foreign_key)?;
					} else if constraint_type == "UNIQUE" {
						for item in list {
							let field_name = &get_field_name(adapter, item["columnName"].as_str().unwrap(), None);
							let value = &Value::String(field_name.clone());

							if let Some(list) = unique_keys.get_mut(name) {
								let list = list.as_array_mut();
								let list = list.unwrap();
								list.push(value.clone());
							} else {
								unique_keys[name] = json!([value]);
							}
						}
					} else if constraint_type == "PRIMARY KEY" {
						for item in list {
							let field_name = &get_field_name(adapter, item["columnName"].as_str().unwrap(), None);
							let value = &Value::String(field_name.clone());
							let list = primary_keys.as_array_mut().unwrap();

							if list.contains(&value) == false {
								list.push(value.clone());
							}

							if object_type.required.contains(&field_name) == false {
								object_type.required.push(field_name.clone());
							}
						}
					}
				}

				for (name, foreign_key) in foreign_keys.as_object_mut().unwrap() {
					let mut candidates = vec![];
					let fields = foreign_key.get_mut("fields").unwrap().as_object_mut().unwrap();

					for (field_name, _field_ref) in &mut *fields {
						if let Some(field) = object_type.properties.get(field_name) {
							if field.as_item().unwrap().schema_data.extensions.contains_key("x-$ref") == false {
								candidates.push(field_name.clone());
							}
						}
					}

					if candidates.len() == 1 {
						fields.remove(name);

						match foreign_key.get("tableRef") {
							Some(table_ref) => set_ref(&mut object_type.properties, &candidates[0], table_ref.as_str().unwrap()),
							None => println!("[DbAdapterPostgres.update_open_api.process_constraints] : missing table_ref from {}.", name),													
						}
					}
				}

				if let Some(list) = adapter.missing_primary_keys.get(schema_name) {
					for column_name in list {
						let value = Value::String(column_name.to_string());

						if primary_keys.as_array().unwrap().contains(&value) == false {
							primary_keys.as_array_mut().unwrap().push(value);
						}

						if object_type.required.contains(column_name) == false {
							object_type.required.push(column_name.clone());
						}
					}
				}

				if let Some(list) = adapter.missing_foreign_keys.get(schema_name) {
					for foreign_key in list {
						for (field_name, _field_ref) in &foreign_key.fields {
							set_ref(&mut object_type.properties, &field_name, &foreign_key.table_ref);
						}
					}
				}

				if object_type.required.len() == 0 {
					println!("[process_columns()] : missing required fields of table {schema_name}");
				}

				schema.schema_data.extensions.insert("x-primaryKeys".to_string(), primary_keys);
				schema.schema_data.extensions.insert("x-uniqueKeys".to_string(), unique_keys);
				schema.schema_data.extensions.insert("x-foreignKeys".to_string(), foreign_keys);
			}

			Ok(())
		}

		#[derive(Deserialize,Debug)]
		#[serde(rename_all = "camelCase")]
		struct SqlInfoTables {
			data_type :String,
			udt_name :String,
			table_name :String,
			column_name :String,
			is_nullable :String,
			is_updatable :String,
			numeric_scale :usize,
			numeric_precision :usize,
			character_maximum_length :usize,
			column_default :String,
			identity_generation :String,
			description :String
		}

		async fn process_columns(adapter :&mut DbAdapterPostgres<'_>, schemas :&mut IndexMap<String, ReferenceOr<Schema>>) -> Result<(), Error> {
			let sql_types = ["boolean", "character varying", "character", "integer", "jsonb", "jsonb array", "numeric", "timestamp without time zone", "timestamp with time zone", "time without time zone", "bigint", "smallint", "text", "date", "double precision", "bytea"];
			let rufs_types = ["boolean", "string", "string", "integer", "object", "array", "number", "date-time", "date-time", "date-time", "integer", "integer", "string", "date-time", "number", "string"];
			let sql_info_tables = "
			select 
			LOWER(TRIM(c.data_type)) as data_type,
			LOWER(TRIM(c.udt_name)) as udt_name,
			LOWER(TRIM(c.table_name)) as table_name,
			LOWER(TRIM(c.column_name)) as column_name,
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
			let rows = adapter.query(sql_info_tables, &[]).await;

			for row in rows {
				let rec: SqlInfoTables = serde_json::from_value(row)?;
				let mut sql_type = rec.data_type.trim().to_lowercase();
				let sql_sub_type = rec.udt_name.trim().to_lowercase();

				if sql_type == "array" && sql_sub_type == "_jsonb" {
					sql_type = "jsonb array".to_string();
				}

				let type_index = sql_types.iter().position(|&item| item == &sql_type);

				if type_index.is_none() {
					println!("DbClientPostgres.getTablesInfo().processColumns() : Invalid Database Type : {sql_type}, full rec : {:?}", rec);
					continue
				}

				let table_name = rec.table_name.to_case(convert_case::Case::Camel);

				let schema = if let Some(schema) = schemas.get_mut(&table_name) {
					schema
				} else {
					schemas.insert(table_name.clone(), ReferenceOr::Item(Schema { schema_data: SchemaData::default(), schema_kind: openapiv3::SchemaKind::Type(openapiv3::Type::Object(ObjectType::default())) }));
					schemas.get_mut(&table_name).unwrap()
				};

				let schema = if let ReferenceOr::Item(schema) = schema {
					schema
				} else {
					continue
				};

				let object_type = match &mut schema.schema_kind {
					SchemaKind::Type(openapiv3::Type::Object(object_type)) => object_type,
					_ => todo!()
				};

				let mut schema_data = SchemaData::default();

				if rec.description.is_empty() == false {
					schema_data.description = Some(rec.description);
				}

				schema_data.nullable = rec.is_nullable == "YES" || rec.is_nullable == "1";    // true,false
				schema_data.extensions.insert("x-updatable".to_string(), Value::Bool(rec.is_updatable == "YES" || rec.is_updatable == "1"));

				if rec.identity_generation.is_empty() == false {
					schema_data.extensions.insert("x-identityGeneration".to_string(), Value::String(rec.identity_generation));
				}
				// SERIAL TYPE
				if rec.column_default.starts_with("nextval") {
					schema_data.extensions.insert("x-identityGeneration".to_string(), Value::String("BY DEFAULT".to_string()));
				}

				let field_name = get_field_name(adapter, &rec.column_name, Some(&mut schema_data));

				if schema_data.nullable == false {
					if object_type.required.contains(&field_name) == false {
						object_type.required.push(field_name.clone());
					}

					schema_data.extensions.insert("x-essential".to_string(), Value::Bool(true));
				}
				// LocalDateTime,ZonedDateTime,Date,Time
				let mut rufs_type = rufs_types[type_index.unwrap()];

				if rufs_type == "number" && rec.numeric_scale == 0 {
					rufs_type = "integer";
				}

				let max_length = if rec.character_maximum_length > 0 {
					Some(rec.character_maximum_length)
				} else {
					None
				};

				let schema_kind = match rufs_type {
					"date-time" => SchemaKind::Type(openapiv3::Type::String(openapiv3::StringType { format: VariantOrUnknownOrEmpty::Item(StringFormat::DateTime), ..Default::default() })),
					"boolean" => SchemaKind::Type(openapiv3::Type::Boolean {  }), 
					"number" => SchemaKind::Type(openapiv3::Type::Number(openapiv3::NumberType { format: VariantOrUnknownOrEmpty::Empty, multiple_of: None, exclusive_minimum: false, exclusive_maximum: false, minimum: None, maximum: None, enumeration: vec![] })),
					"integer" => SchemaKind::Type(openapiv3::Type::Integer(openapiv3::IntegerType { format: VariantOrUnknownOrEmpty::Empty, multiple_of: None, exclusive_minimum: false, exclusive_maximum: false, minimum: None, maximum: None, enumeration: vec![] })), 
					"array"=> SchemaKind::Type(openapiv3::Type::Array(openapiv3::ArrayType { items: Some(ReferenceOr::Item(Box::new(Schema {schema_data: SchemaData::default(), schema_kind: SchemaKind::Type(openapiv3::Type::String(openapiv3::StringType { format: VariantOrUnknownOrEmpty::Empty, pattern: None, enumeration: vec![], min_length: None, max_length: None }))}))), min_items: None, max_items: None, unique_items: false })), 
					"object" => SchemaKind::Type(openapiv3::Type::Object(ObjectType { properties: IndexMap::default(), required: vec![], additional_properties: None, min_properties: None, max_properties: None })),
					_ => SchemaKind::Type(openapiv3::Type::String(openapiv3::StringType { format: VariantOrUnknownOrEmpty::Empty, pattern: None, enumeration: vec![], min_length: None, max_length })), 
				};


				if rec.column_default.is_empty() == false {
					schema_data.default = match rufs_type {
						"integer" => Some(Value::Number(Number::from(rec.column_default.parse::<i64>().unwrap()))),
						"number" => Some(Value::Number(Number::from_f64(rec.column_default.parse::<f64>().unwrap()).unwrap())),
						_ => Some(Value::String(rec.column_default.replace("'", ""))), // TODO : usar regexp ^'(.*)'$ // 'pt-br'::character varying,
					}
				}

				if ["number"].contains(&rufs_type) {
					schema_data.extensions.insert("x-scale".to_string(), Value::Number(Number::from(rec.numeric_scale)));                           // > 0 // 3,2,1
					schema_data.extensions.insert("x-precision".to_string(), Value::Number(Number::from(rec.numeric_precision)));                   // > 0
				}

				object_type.properties.insert(field_name, ReferenceOr::Item(Box::new(Schema { schema_data, schema_kind })));
			}

			Ok(())
		}

		let mut schemas : IndexMap<String, ReferenceOr<Schema>> = IndexMap::new();
		process_columns(self, &mut schemas).await?;
		process_constraints(self, &mut schemas).await?;
		options.schemas = schemas;
		//self.openapi = openapi;
		openapi.fill(options).unwrap();
		Ok(())
	}

	async fn create_table(&self, name :&str, schema :&Schema) -> Result<(), Error> {
		fn gen_sql_column_description(field_name :&str, field :&Schema) -> Result<String, Error> {
			let typ = match &field.schema_kind {
				SchemaKind::Type(typ) => typ,
				_ => todo!(),
			};

			let name = field_name.to_case(convert_case::Case::Snake);

			let sql_not_null = if field.schema_data.nullable != true {
				"NOT NULL"
			} else {
				""
			};

			let str = match typ {
				openapiv3::Type::String(x) => {
					if let Some(max_length) = x.max_length {
						let sql_type = if max_length > 0 && max_length < 32 {
							"character".to_string()
						} else {
							"varchar".to_string()
						};

						format!("{} {}({}) {}", name, sql_type, max_length, sql_not_null)
					} else {
						format!("{} {} {}", name, "varchar", sql_not_null)
					}
				},
				openapiv3::Type::Boolean {  } => {
					format!("{} {} {}", name, "boolean", sql_not_null)
				},
				openapiv3::Type::Number(_) => {
					format!("{} {} {}", name, "numeric", sql_not_null)
				},
				openapiv3::Type::Object(_) => {
					format!("{} {} {}", name, "jsonb", sql_not_null)
				},
				openapiv3::Type::Array(_) => {
					format!("{} {} {}", name, "jsonb array", sql_not_null)
				},
				openapiv3::Type::Integer(_) => {
					if let Some(identity_generation) = field.schema_data.extensions.get("x-identityGeneration") {
						let identity_generation = identity_generation.as_str().unwrap();
						format!("{} {} {}", name, "int", format!("GENERATED {} AS IDENTITY", identity_generation))
					} else {
						format!("{} {} {}", name, "int", sql_not_null)
					}
				},
			};

			Ok(str)
		}

		let properties = match &schema.schema_kind {
			SchemaKind::Type(typ) => match typ {
				openapiv3::Type::Object(object_type) => &object_type.properties,
				_ => todo!()
			},
			SchemaKind::Any(x) => &x.properties,
			_ => todo!(),
		};		
		// add foreign keys
		let mut list = vec![];

		for (field_name, field) in properties {
			match field {
				ReferenceOr::Reference { reference } => {
					println!("[DbAdapterPostgres.create_table] : {}", reference);
					todo!()
				},
				ReferenceOr::Item(field) => {
					let field_description = gen_sql_column_description(field_name, field)?;
					list.push(field_description);
				},
			}
		}

		for (field_name, field) in properties {
			if let Some(reference) = field.as_item().unwrap().schema_data.extensions.get("x-$ref") {
				let reference = reference.as_str().unwrap();
				let table_out = OpenAPI::get_schema_name_from_ref(reference);
				let table_out = table_out.to_case(convert_case::Case::Snake);
				list.push(format!("FOREIGN KEY({}) REFERENCES {}", field_name.to_case(convert_case::Case::Snake), table_out));
			}
		}

		let mut list_primary_keys = vec![];

		if let Some(primary_keys) = schema.schema_data.extensions.get("x-primaryKeys") {
			let primary_keys = primary_keys.as_array().unwrap();

			for field_name in primary_keys.into_iter() {
				let field_name = field_name.as_str().unwrap();
				list_primary_keys.push(field_name.to_case(convert_case::Case::Snake));
			}
		}

		let table_name = name.to_case(convert_case::Case::Snake);
		let sql = format!("CREATE TABLE IF NOT EXISTS {} ({}, PRIMARY KEY({}))", table_name, list.join(", "), list_primary_keys.join(", "));
		println!("[DbAdapterPostgres.create_table] : {}", sql);
		self.exec(&sql).await?;
		//self.update_open_api(self.openapi, FillOpenApiOptions{request_body_content_type: self.db_config.request_body_content_type})?;
		Ok(())
	}

}
