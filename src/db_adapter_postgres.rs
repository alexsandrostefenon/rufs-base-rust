use std::{io::Error, sync::{Arc}};

use convert_case::Casing;
use openapiv3::OpenAPI;
use serde_json::{Value, Number, json};
use tokio_postgres::{NoTls, Client, Row, types::{Type, ToSql}};

use crate::{entity_manager::EntityManager, openapi::RufsOpenAPI};

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
    client: Option<Arc<Client>>,
    //client: Option<Arc<RwLock<Client>>>,
    tmp: Value,
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
	missingPrimaryKeys         map[string][]string
	missingForeignKeys         map[string]map[string]string
	aliasMap                   map[string]string
	aliasMapExternalToInternal map[string]any
	openapi                    *OpenApi
	client                     *sql.DB
	sqlTypes                   []string
	rufsTypes                  []string
}

fn Connect() (err error) {
	if self.dbConfig.limitQuery == 0 {
		self.dbConfig.limitQuery = 1000
	}

	dataSourceName := fmt.Sprintf("postgres://%s:%s@localhost:5432/%s", self.dbConfig.user, self.dbConfig.password, self.dbConfig.database)
	self.dbConfig.driverName = "pgx"
	self.client, err = sql.Open(self.dbConfig.driverName, dataSourceName)

	if err != nil {
		return err
	}

	return nil
}

fn Disconnect() error {
	return self.client.Close()
}
*/
    fn build_query<'a>(&self, query_params:&'a Value, params :&mut Vec<&'a (dyn ToSql + Sync)>, order_by :&Vec<String>) -> String {
		fn build_conditions<'a> (query_params:&'a Value, params: &mut Vec<&'a (dyn ToSql + Sync)>, operator:&str, conditions : &mut Vec<String>) {
			let mut count = 1;
			let _null : Option<bool> = None;

			for (field_name, field) in query_params.as_object().unwrap() {
				let field_name = field_name.to_case(convert_case::Case::Snake);
				let param_id = format!("${}", count);
				count += 1;

				println!("{field_name} : {}", field);

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
}

#[tide::utils::async_trait]
impl EntityManager for DbAdapterPostgres<'_> {
    fn insert(&self, _openapi: &OpenAPI, table_name :&str, obj :&Value) -> Result<Value, Error> {
        println!("[DbAdapterPostgres.find({}, {})]", table_name, obj.to_string());
        Ok(obj.clone())
    }

/*
fn Insert(schemaName:&str, obj map[string]any) (map[string]any, error) {
	buildInsertSql := func(schemaName:&str, schema *Schema, obj:&Value, params *[]any) string {
		tableName := CamelToUnderscore(schemaName)
		strFields := []string{}
		strValues := []string{}
		idx := 1

		for fieldName, value := range obj {
			if property, ok := schema.Properties[fieldName]; ok && property.IdentityGeneration != "" && value == nil {
				continue
			}
			//			if (self.options.aliasMapExternalToInternal[fieldName] != null) fieldName = self.options.aliasMapExternalToInternal[fieldName];
			strFields = append(strFields, CamelToUnderscore(fieldName))
			strValues = append(strValues, fmt.Sprintf("$%d", idx))
			idx++

			switch v := value.(type) {
			case map[string]any:
				b, _ := json.Marshal(v)
				*params = append(*params, string(b))
			case []any:
				elements := []pgtype.JSONB{}

				for _, item := range v {
					b, _ := json.Marshal(item)
					element := pgtype.JSONB{Bytes: b, Status: pgtype.Present}
					elements = append(elements, element)
				}

				dimensions := []pgtype.ArrayDimension{{Length: int32(len(elements)), LowerBound: 1}}
				list := pgtype.JSONBArray{Elements: elements, Dimensions: dimensions, Status: pgtype.Present}
				*params = append(*params, list)
			default:
				*params = append(*params, self.openapi.getValueFromSchema(schema, fieldName, obj))
			}
		}

		return fmt.Sprintf(`INSERT INTO %s (%s) VALUES (%s) RETURNING *;`, tableName, strings.Join(strFields, ","), strings.Join(strValues, ","))
	}

	schema, ok := self.openapi.getSchemaFromSchemas(schemaName)

	if !ok {
		return nil, fmt.Errorf(`[dbClientSql.Insert] : Missing schema %s`, schemaName)
	}

	params := []any{}
	sql := buildInsertSql(schemaName, schema, obj, &params)
	fmt.Println(sql)
	rows, err := self.client.Query(sql, params...)

	if err != nil {
		return nil, err
	}

	if rows.Next() == false {
		return nil, fmt.Errorf(`Failt to insert : %s : %s`, sql, rows.Err())
	}

	item, err := self.getMapFromRow(rows, schema)

	if err != nil {
		return nil, err
	}

	return item, nil
}
*/
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
    let list = self.client.as_ref().unwrap().query(&sql, params).await.unwrap();
    return self.get_json_list(&list);
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

fn update<'a>(&'a self, _openapi: &OpenAPI, table_name :&str, key :&Value, obj :&'a Value) -> Result<&'a Value, Error> {
    println!("[DbAdapterPostgres.find({}, {}, {})]", table_name, key, obj.to_string());
    Ok(&self.tmp)
}

/*
fn Update(schemaName:&str, key:&Value, obj map[string]any) (map[string]any, error) {
	schema, ok := self.openapi.getSchemaFromSchemas(schemaName)

	if !ok {
		return nil, fmt.Errorf(`[dbClientSql.Insert] : Missing schema %s`, schemaName)
	}

	tableName := CamelToUnderscore(schemaName)
	params := []any{}
	sqlQuery := self.buildQuery(key, &params, []string{})
	list := []string{}
	idx := 1

	for fieldName, value := range obj {
		if property, ok := schema.Properties[fieldName]; ok && property.IdentityGeneration != "" && value == nil {
			continue
		}

		strField := CamelToUnderscore(fieldName)
		strValue := fmt.Sprintf("$%d", idx)
		list = append(list, fmt.Sprintf("%s=%s", strField, strValue))
		idx++

		switch v := value.(type) {
		case map[string]any:
			b, _ := json.Marshal(v)
			params = append(params, string(b))
		case []any:
			elements := []pgtype.JSONB{}

			for _, item := range v {
				b, _ := json.Marshal(item)
				element := pgtype.JSONB{Bytes: b, Status: pgtype.Present}
				elements = append(elements, element)
			}

			dimensions := []pgtype.ArrayDimension{{Length: int32(len(elements)), LowerBound: 1}}
			list := pgtype.JSONBArray{Elements: elements, Dimensions: dimensions, Status: pgtype.Present}
			params = append(params, list)
		default:
			params = append(params, self.openapi.getValueFromSchema(schema, fieldName, obj))
		}
	}

	sql := fmt.Sprintf(`UPDATE %s SET %s %s RETURNING *`, tableName, strings.Join(list, ","), sqlQuery)
	fmt.Println(sql)
	rows, err := self.client.Query(sql, params...)

	if err != nil {
		return nil, err
	}

	if rows.Next() == false {
		return nil, fmt.Errorf(`Failt to update : %s : %s`, sql, rows.Err())
	}

	item, err := self.getMapFromRow(rows, schema)

	if err != nil {
		return nil, err
	}

	return item, nil
}
*/
fn delete_one(&self, _openapi: &OpenAPI, table_name: &str, key: &Value) -> Result<(), Error> {
    println!("[DbAdapterPostgres.delete_one({}, {})]", table_name, key);
    Ok(())
}
/*
fn DeleteOne(schemaName:&str, key map[string]any) error {
	tableName := CamelToUnderscore(schemaName)
	params := []any{}
	sqlQuery := self.buildQuery(key, &params, []string{})
	sql := fmt.Sprintf(`DELETE FROM %s %s`, tableName, sqlQuery)
	fmt.Println(sql)
	result, err := self.client.Exec(sql, params...)

	if err != nil {
		return err
	}

	if numRows, err := result.RowsAffected(); err != nil || numRows != 1 {
		return fmt.Errorf(`[dbClientSql.DeleteOne] : wrong delete numRows = %d, err = %s`, numRows, err)
	}

	return err
}

fn UpdateOpenApi(openapi *OpenApi, options FillOpenApiOptions) error {
	getFieldName := func(columnName:&str, field *Schema) (fieldName string) {
		fieldName = UnderscoreToCamel(strings.ToLower(columnName), false)
		fieldNameLowerCase := strings.ToLower(fieldName)

		for aliasMapName, value := range self.aliasMap {
			if strings.ToLower(aliasMapName) == fieldNameLowerCase {
				if field != nil {
					field.InternalName = fieldName

					if len(value) > 0 {
						self.aliasMapExternalToInternal[value] = fieldName
					}
				}

				if len(value) > 0 {
					fieldName = value
				} else {
					fieldName = aliasMapName
				}

				break
			}
		}

		return fieldName
	}

	setRef := func(schema *Schema, fieldName:&str, tableRef string) {
		field := schema.Properties[fieldName]

		if field != nil {
			field.Ref = "#/components/schemas/" + tableRef
		} else {
			log.Printf(`${self.constructor.name}.getTablesInfo.processConstraints.setRef : field ${fieldName} not exists in schema ${schema.name}`)
		}
	}

	processConstraints := func(schemas map[string]*Schema) error {
		sqlInfoConstraints :=
			"SELECT table_name,constraint_name,constraint_type FROM information_schema.table_constraints ORDER BY table_name,constraint_name"
		sqlInfoConstraintsFields :=
			"SELECT constraint_name,column_name,ordinal_position FROM information_schema.key_column_usage ORDER BY constraint_name,ordinal_position"
		sqlInfoConstraintsFieldsRef :=
			"SELECT constraint_name,table_name,column_name FROM information_schema.constraint_column_usage"
		result, err := self.getArrayMap(sqlInfoConstraints, []any{}, nil)

		if err != nil {
			return err
		}

		resultFields, err := self.getArrayMap(sqlInfoConstraintsFields, []any{}, nil)

		if err != nil {
			return err
		}

		resultFieldsRef, err := self.getArrayMap(sqlInfoConstraintsFieldsRef, []any{}, nil)

		if err != nil {
			return err
		}

		for schemaName, schema := range schemas {
			schema.ForeignKeys = map[string]ForeignKey{}
			tableName := CamelToUnderscore(schemaName)

			for _, constraint := range result {
				if strings.TrimSpace(strings.ToLower(constraint["tableName"].(string))) != tableName {
					continue
				}

				if constraint["constraintName"] == "" {
					continue
				}

				constraintName := strings.TrimSpace(constraint["constraintName"].(string))
				name := UnderscoreToCamel(strings.ToLower(constraintName), false)
				list := []map[string]any{}
				for _, item := range resultFields {
					if strings.TrimSpace(item["constraintName"].(string)) == constraintName {
						list = append(list, item)
					}
				}

				listRef := []map[string]any{}
				for _, item := range resultFieldsRef {
					if strings.TrimSpace(item["constraintName"].(string)) == constraintName {
						listRef = append(listRef, item)
					}
				}

				constraintType := strings.TrimSpace(constraint["constraintType"].(string))

				if constraintType == "FOREIGN KEY" {
					foreignKey := ForeignKey{Fields: []string{}, FieldsRef: []string{}}

					for _, item := range list {
						foreignKey.Fields = append(foreignKey.Fields, getFieldName(item["columnName"].(string), nil))
					}

					for _, itemRef := range listRef {
						foreignKey.FieldsRef = append(foreignKey.FieldsRef, getFieldName(itemRef["columnName"].(string), nil))
						tableRef := UnderscoreToCamel(strings.ToLower(itemRef["tableName"].(string)), false)

						if foreignKey.TableRef == "" || foreignKey.TableRef == tableRef {
							foreignKey.TableRef = tableRef
						} else {
							log.Printf(`[${self.constructor.name}.getOpenApi().processConstraints()] : tableRef already defined : new (${tableRef}, old (${foreignKey.tableRef}))`)
						}
					}

					if len(foreignKey.Fields) != len(foreignKey.FieldsRef) {
						log.Printf(`[${self.constructor.name}.getOpenApi().processConstraints()] : fields and fieldsRef length don't match : fields (${foreignKey.fields.toString()}, fieldsRef (${foreignKey.fieldsRef.toString()}))`)
						continue
					}

					if len(foreignKey.Fields) == 1 {
						setRef(schema, foreignKey.Fields[0], foreignKey.TableRef)
						continue
					}

					if len(foreignKey.Fields) > 1 && slices.Index(foreignKey.Fields, foreignKey.TableRef) >= 0 {
						setRef(schema, foreignKey.TableRef, foreignKey.TableRef)
					}

					schema.ForeignKeys[name] = foreignKey
				} else if constraintType == "UNIQUE" {
					schema.UniqueKeys[name] = []string{}

					for _, item := range list {
						fieldName := getFieldName(item["columnName"].(string), nil)

						if slices.Index(schema.UniqueKeys[name], fieldName) < 0 {
							schema.UniqueKeys[name] = append(schema.UniqueKeys[name], fieldName)
						}
					}
				} else if constraintType == "PRIMARY KEY" {
					for _, item := range list {
						fieldName := getFieldName(item["columnName"].(string), nil)

						if slices.Index(schema.PrimaryKeys, fieldName) < 0 {
							schema.PrimaryKeys = append(schema.PrimaryKeys, fieldName)
						}

						if slices.Index(schema.Required, fieldName) < 0 {
							schema.Required = append(schema.Required, fieldName)
						}
					}
				}
			}

			for name, foreignKey := range schema.ForeignKeys {
				candidates := []string{}

				for _, fieldName := range foreignKey.Fields {
					if field, ok := schema.Properties[fieldName]; ok && field.Ref == "" {
						candidates = append(candidates, fieldName)
					}
				}

				if len(candidates) == 1 {
					setRef(schema, candidates[0], foreignKey.TableRef)
					delete(schema.ForeignKeys, name)
				}
			}

			if list, ok := self.missingPrimaryKeys[schemaName]; ok {
				for _, columnName := range list {
					if slices.Index(schema.PrimaryKeys, columnName) < 0 {
						schema.PrimaryKeys = append(schema.PrimaryKeys, columnName)
					}

					if slices.Index(schema.Required, columnName) < 0 {
						schema.Required = append(schema.Required, columnName)
					}
				}
			}

			if list, ok := self.missingForeignKeys[schemaName]; ok {
				for fieldName, tableRef := range list {
					setRef(schema, fieldName, tableRef)
				}
			}

			if len(schema.Required) == 0 {
				log.Printf(`[${self.constructor.name}.getOpenApi().processColumns()] missing required fields of table ${schemaName}`)
			}
		}

		return nil
	}

	processColumns := func() (map[string]*Schema, error) {
		self.sqlTypes = []string{"boolean", "character varying", "character", "integer", "jsonb", "jsonb array", "numeric", "timestamp without time zone", "timestamp with time zone", "time without time zone", "bigint", "smallint", "text", "date", "double precision", "bytea"}
		self.rufsTypes = []string{"boolean", "string", "string", "integer", "object", "array", "number", "date-time", "date-time", "date-time", "integer", "integer", "string", "date-time", "number", "string"}
		sqlInfoTables := `
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
		`
		rows, err := self.client.Query(sqlInfoTables)

		if err != nil {
			return nil, err
		}

		schemas := map[string]*Schema{}

		for rows.Next() {
			rec, _ := self.getMapFromRow(rows, nil)
			sqlType := strings.ToLower(strings.Trim(rec["dataType"].(string), " "))
			sqlSubType := strings.ToLower(strings.Trim(rec["udtName"].(string), " "))

			if sqlType == "array" && sqlSubType == "_jsonb" {
				sqlType = "jsonb array"
			}

			typeIndex := slices.Index(self.sqlTypes, sqlType)

			if typeIndex < 0 {
				log.Printf(`DbClientPostgres.getTablesInfo().processColumns() : Invalid Database Type : ${rec["dataType"].trim().toLowerCase()}, full rec : ${JSON.stringify(rec)}`)
				continue
			}

			tableName := UnderscoreToCamel(rec["tableName"].(string), false)

			if schemas[tableName] == nil {
				schemas[tableName] = &Schema{Type: "object", Properties: map[string]*Schema{}, UniqueKeys: map[string][]string{}}
			}

			schema := schemas[tableName]
			field := &Schema{}
			fieldName := getFieldName(rec["columnName"].(string), field)
			field.UniqueKeys = nil
			field.Type = self.rufsTypes[typeIndex] // LocalDateTime,ZonedDateTime,Date,Time

			if field.Type == "date-time" {
				field.Type = "string"
				field.Format = "date-time"
			}

			field.Nullable = rec["isNullable"] == "YES" || rec["isNullable"] == 1    // true,false
			field.Updatable = rec["isUpdatable"] == "YES" || rec["isUpdatable"] == 1 // true,false
			field.Scale = int(rec["numericScale"].(int64))                           // > 0 // 3,2,1
			field.Precision = int(rec["numericPrecision"].(int64))                   // > 0
			if rec["columnDefault"] != nil {
				field.Default = rec["columnDefault"].(string) // 'pt-br'::character varying
			}
			if rec["description"] != nil {
				field.Description = rec["description"].(string)
			}

			if field.Nullable != true {
				if slices.Index(schema.Required, fieldName) < 0 {
					schema.Required = append(schema.Required, fieldName)
				}

				field.Essential = true
			}

			if strings.HasPrefix(sqlType, "character") == true {
				field.MaxLength = int(rec["characterMaximumLength"].(int64)) // > 0 // 255
			}

			if field.Type == "number" && field.Scale == 0 {
				field.Type = "integer"
			}

			if field.Default != "" && field.Default[:1] == "'" && len(field.Default) > 2 {
				posEnd := strings.LastIndex(field.Default, "'")

				if field.Type == "string" && posEnd > 1 {
					field.Default = field.Default[1:posEnd]
				} else {
					field.Default = ""
				}
			}

			if (field.Type == "integer" || field.Type == "number") && len(field.Default) > 0 {
				if _, err := strconv.ParseFloat(field.Default, 64); err != nil {
					field.Default = ""
				}
			}

			if rec["identityGeneration"] != nil {
				field.IdentityGeneration = rec["identityGeneration"].(string)
			}
			// SERIAL TYPE
			if strings.HasPrefix(field.Default, "nextval") {
				field.IdentityGeneration = "BY DEFAULT"
			}

			if field.Type == "array" {
				field.Items = &Schema{}
			}

			schema.Properties[fieldName] = field
		}

		return schemas, nil
	}

	schemas, _ := processColumns()
	processConstraints(schemas)
	options.schemas = schemas
	self.openapi = openapi
	openapi.FillOpenApi(options)
	return nil
}

fn CreateTable(name:&str, schema *Schema) (sql.Result, error) {
	genSqlColumnDescription := func(fieldName:&str, field *Schema) (string, error) {
		if field.Type == "" {
			if field.IdentityGeneration != "" {
				field.Type = "integer"
			} else {
				field.Type = "string"
			}
		}

		pos := slices.Index(self.rufsTypes, field.Type)

		if pos < 0 {
			return "", fmt.Errorf(`[CreateTable(%s).genSqlColumnDescription(%s)] Missing rufsType equivalent of %s`, name, fieldName, field.Type)
		}

		sqlType := self.sqlTypes[pos]

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
		return fmt.Sprintf(`%s %s%s %s %s`, CamelToUnderscore(fieldName), sqlType, sqlLengthScale, sqlDefault, sqlNotNull), nil
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
